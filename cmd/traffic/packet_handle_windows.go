package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Sunmedalia/traffic/internal/session"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/windows"
)

const (
	winDivertPacketBufferBytes = 512 << 10
	winDivertParamQueueLength  = 0
	winDivertParamQueueTime    = 1
	winDivertParamQueueSize    = 2
	winDivertQueueLengthValue  = 16384
	winDivertQueueTimeMsValue  = 8000
	winDivertQueueSizeBytes    = 32 << 20
)

var (
	kernel32DLL       = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerfFreq = kernel32DLL.NewProc("QueryPerformanceFrequency")
	procQueryPerfCnt  = kernel32DLL.NewProc("QueryPerformanceCounter")
)

func winDivertPath() string { return session.BundleFile("deps/windivert/WinDivert.dll", "") }

func listCaptureDevices() ([]pcap.Interface, error) {
	if winDivertPath() == "" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return nil, fmt.Errorf("采集依赖不完整：请解压完整 traffic Windows 包（缺少 deps/windivert/WinDivert.dll）；%w", err)
		}
		return devices, nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := []pcap.Interface{{Name: "windivert", Description: "全部本机接口及回环（随包 WinDivert）"}}
	for _, iface := range interfaces {
		device := pcap.Interface{Name: "windivert:" + strconv.Itoa(iface.Index), Description: iface.Name}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, network, err := net.ParseCIDR(address.String())
			if err == nil {
				device.Addresses = append(device.Addresses, pcap.InterfaceAddress{IP: ip, Netmask: network.Mask})
			}
		}
		result = append(result, device)
	}
	return result, nil
}

func bundledPacketInterfaces(input string) ([]string, bool, error) {
	if winDivertPath() == "" {
		return nil, false, nil
	}
	if input == "" || input == "any" || input == "windivert" {
		return []string{"windivert"}, true, nil
	}
	devices, err := listCaptureDevices()
	if err != nil {
		return nil, true, err
	}
	available := map[string]string{}
	for _, device := range devices {
		if device.Name != "windivert" {
			available[device.Name] = device.Name
			available[device.Description] = device.Name
		}
	}
	var result []string
	seen := map[string]bool{}
	for _, name := range strings.Split(input, ",") {
		canonical, ok := available[name]
		if !ok || seen[canonical] {
			return nil, true, fmt.Errorf("未知或重复接口 %q；运行 traffic doctor 查看接口", name)
		}
		result = append(result, canonical)
		seen[canonical] = true
	}
	return result, true, nil
}

func sampleQPCAnchor() (anchorUTC time.Time, anchorTicks int64, freq int64) {
	var f, c int64
	okF, _, _ := procQueryPerfFreq.Call(uintptr(unsafe.Pointer(&f)))
	before := time.Now()
	okC, _, _ := procQueryPerfCnt.Call(uintptr(unsafe.Pointer(&c)))
	anchorUTC = before.Add(time.Since(before) / 2).UTC()
	if okF != 0 && okC != 0 && f > 0 && c > 0 {
		return anchorUTC, c, f
	}
	return anchorUTC, 0, 0
}

type winDivertPacketHandle struct {
	handle                  windows.Handle
	event                   windows.Handle
	recvEx, shutdown, close *windows.Proc
	overlapped              windows.Overlapped
	buf                     []byte
	addrBuf                 []byte
	recvLen                 uint32
	addrLen                 uint32
	snaplen                 int
	anchorUTC               time.Time
	anchorTicks             int64
	qpcFreq                 int64
	*winDivertBatchQueue
	errCh              chan error
	abortCh            chan struct{}
	pumpDone           chan struct{}
	closing            atomic.Bool
	lastPollNano       atomic.Int64
	timestampFallbacks atomic.Uint64
	debugBatches       int
	stopOnce           sync.Once
	closeOnce          sync.Once
}

func openLivePacket(ctx context.Context, iface string) (packetHandle, error) {
	if !strings.HasPrefix(iface, "windivert") {
		handle, err := openPCAPLive(iface)
		if err != nil {
			return nil, err
		}
		return handle, nil
	}
	path := winDivertPath()
	if path == "" {
		return nil, fmt.Errorf("完整采集包缺少 WinDivert 运行依赖")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, fmt.Errorf("请在管理员 PowerShell 中运行 traffic capture；doctor 无需加载驱动")
	}
	// Use an absolute, application-owned DLL path and restrict dependency lookup.
	dllHandle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("加载随包 WinDivert: %w", err)
	}
	dll := &windows.DLL{Name: filepath.Base(path), Handle: dllHandle}
	open, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		dll.Release()
		return nil, err
	}
	recvEx, err := dll.FindProc("WinDivertRecvEx")
	if err != nil {
		dll.Release()
		return nil, err
	}
	setParam, _ := dll.FindProc("WinDivertSetParam")
	shutdown, err := dll.FindProc("WinDivertShutdown")
	if err != nil {
		dll.Release()
		return nil, err
	}
	closeProc, err := dll.FindProc("WinDivertClose")
	if err != nil {
		dll.Release()
		return nil, err
	}
	var ports []int
	for port := range capturePorts {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	clauses := make([]string, 0, len(ports))
	for _, port := range ports {
		clauses = append(clauses, fmt.Sprintf("tcp.SrcPort == %d or tcp.DstPort == %d", port, port))
	}
	filter := "tcp"
	if len(clauses) > 0 {
		filter += " and (" + strings.Join(clauses, " or ") + ")"
	}
	if suffix, ok := strings.CutPrefix(iface, "windivert:"); ok {
		index, err := strconv.Atoi(suffix)
		if err != nil || index < 1 {
			dll.Release()
			return nil, fmt.Errorf("invalid WinDivert interface %q", iface)
		}
		filter += fmt.Sprintf(" and ifIdx == %d", index)
	}
	bytes, err := windows.BytePtrFromString(filter)
	if err != nil {
		dll.Release()
		return nil, err
	}
	// NETWORK=0; SNIFF=1 copies without diversion, RECV_ONLY=4 prohibits injection.
	anchorUTC, anchorTicks, qpcFreq := sampleQPCAnchor()
	value, _, callErr := open.Call(uintptr(unsafe.Pointer(bytes)), 0, 0, 1|4)
	if windows.Handle(value) == windows.InvalidHandle {
		dll.Release()
		return nil, fmt.Errorf("启动随包 WinDivert 驱动失败: %w（检查管理员权限及系统驱动策略）", callErr)
	}
	handle := windows.Handle(value)
	if setParam != nil {
		_, _, _ = setParam.Call(uintptr(handle), winDivertParamQueueLength, winDivertQueueLengthValue)
		_, _, _ = setParam.Call(uintptr(handle), winDivertParamQueueTime, winDivertQueueTimeMsValue)
		_, _, _ = setParam.Call(uintptr(handle), winDivertParamQueueSize, winDivertQueueSizeBytes)
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		shutdown.Call(uintptr(handle), 1)
		closeProc.Call(uintptr(handle))
		dll.Release()
		return nil, fmt.Errorf("创建 WinDivert 事件句柄失败: %w", err)
	}
	abortCh := make(chan struct{})
	result := &winDivertPacketHandle{
		handle:              handle,
		event:               event,
		recvEx:              recvEx,
		shutdown:            shutdown,
		close:               closeProc,
		buf:                 make([]byte, winDivertPacketBufferBytes),
		addrBuf:             make([]byte, winDivertBatchMax*winDivertAddrSize),
		snaplen:             int(captureSnapshotLength()),
		anchorUTC:           anchorUTC,
		anchorTicks:         anchorTicks,
		qpcFreq:             qpcFreq,
		winDivertBatchQueue: newWinDivertBatchQueue(abortCh),
		errCh:               make(chan error, 1),
		abortCh:             abortCh,
		pumpDone:            make(chan struct{}),
	}
	if os.Getenv("TRAFFIC_WINDIVERT_DEBUG") == "1" {
		result.debugBatches = 32
	}
	result.lastPollNano.Store(anchorUTC.UnixNano())
	go result.pump()
	go func() {
		select {
		case <-ctx.Done():
			result.requestStop()
		case <-result.pumpDone:
		}
	}()
	// Keep this DLL loaded for process lifetime: cancellation may still be
	// unwinding an overlapped receive if the kernel driver takes time to complete.
	return result, nil
}

func (h *winDivertPacketHandle) takeTimestampFallbacks() uint64 {
	return h.timestampFallbacks.Swap(0)
}

func (h *winDivertPacketHandle) debugBatch(receivedAt time.Time, packets []winDivertBatchPacket, err error) {
	if h.debugBatches <= 0 {
		return
	}
	h.debugBatches--
	var firstTicks, lastTicks int64
	var firstTime, lastTime time.Time
	if len(packets) > 0 {
		firstTicks = int64(binary.LittleEndian.Uint64(h.addrBuf[:8]))
		offset := (len(packets) - 1) * winDivertAddrSize
		lastTicks = int64(binary.LittleEndian.Uint64(h.addrBuf[offset : offset+8]))
		firstTime = packets[0].ci.Timestamp
		lastTime = packets[len(packets)-1].ci.Timestamp
	}
	fmt.Fprintf(os.Stderr, "WinDivert batch bytes=%d addr_bytes=%d packets=%d anchor_ticks=%d qpc_hz=%d first_ticks=%d last_ticks=%d receive_utc=%s first_utc=%s last_utc=%s error=%v\n",
		h.recvLen, h.addrLen, len(packets), h.anchorTicks, h.qpcFreq, firstTicks, lastTicks,
		receivedAt.Format(time.RFC3339Nano), firstTime.Format(time.RFC3339Nano), lastTime.Format(time.RFC3339Nano), err)
}

func (h *winDivertPacketHandle) recordErr(err error) {
	if err == nil {
		return
	}
	select {
	case h.errCh <- err:
	default:
	}
}

func (h *winDivertPacketHandle) requestStop() {
	h.stopOnce.Do(func() {
		h.closing.Store(true)
		// WINDIVERT_SHUTDOWN_RECV=1 stops queueing new packets and wakes empty receives with ERROR_NO_DATA.
		if ok, _, err := h.shutdown.Call(uintptr(h.handle), 1); ok == 0 {
			h.recordErr(fmt.Errorf("stop WinDivert receive: %w", err))
		}
	})
}

func (h *winDivertPacketHandle) pump() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// The driver may retain these addresses until overlapped I/O completes.
	var pinned runtime.Pinner
	pinned.Pin(&h.buf[0])
	pinned.Pin(&h.addrBuf[0])
	pinned.Pin(&h.addrLen)
	pinned.Pin(&h.overlapped)
	defer pinned.Unpin()
	defer func() {
		// Serialize shutdown with handle release, including when the pump fails.
		h.requestStop()
		_ = windows.CloseHandle(h.event)
		h.close.Call(uintptr(h.handle))
		close(h.batches)
		close(h.pumpDone)
	}()

	for {
		h.lastPollNano.Store(time.Now().UnixNano())
		if err := windows.ResetEvent(h.event); err != nil {
			h.recordErr(fmt.Errorf("reset WinDivert receive event: %w", err))
			return
		}
		h.overlapped = windows.Overlapped{HEvent: h.event}
		h.recvLen = 0
		h.addrLen = uint32(len(h.addrBuf))

		ok, _, callErr := h.recvEx.Call(
			uintptr(h.handle),
			uintptr(unsafe.Pointer(&h.buf[0])),
			uintptr(len(h.buf)),
			uintptr(unsafe.Pointer(&h.recvLen)),
			0,
			uintptr(unsafe.Pointer(&h.addrBuf[0])),
			uintptr(unsafe.Pointer(&h.addrLen)),
			uintptr(unsafe.Pointer(&h.overlapped)),
		)
		receivedAt := time.Now().UTC()
		h.lastPollNano.Store(receivedAt.UnixNano())

		var recvErr error
		if ok != 0 {
			if h.recvLen == 0 {
				recvErr = windows.GetOverlappedResult(h.handle, &h.overlapped, &h.recvLen, false)
			}
		} else if errors.Is(callErr, windows.ERROR_IO_PENDING) {
			var shutdownDeadline time.Time
			for {
				ev, waitErr := windows.WaitForSingleObject(h.event, 100)
				receivedAt = time.Now().UTC()
				h.lastPollNano.Store(receivedAt.UnixNano())
				if ev == windows.WAIT_OBJECT_0 {
					recvErr = windows.GetOverlappedResult(h.handle, &h.overlapped, &h.recvLen, false)
					break
				}
				if ev == uint32(windows.WAIT_TIMEOUT) {
					if !h.closing.Load() {
						continue
					}
					if shutdownDeadline.IsZero() {
						shutdownDeadline = time.Now().Add(500 * time.Millisecond)
					}
					if time.Now().Before(shutdownDeadline) {
						continue
					}
				}
				if waitErr == nil {
					waitErr = errors.New("WinDivert receive did not complete after shutdown")
				}
				h.recordErr(waitErr)
				_ = windows.CancelIoEx(h.handle, &h.overlapped)
				// Keep the handle, event and Go buffers live until the driver is
				// done with them. Close bounds how long its caller waits.
				_ = windows.GetOverlappedResult(h.handle, &h.overlapped, &h.recvLen, true)
				return
			}
		} else {
			recvErr = callErr
		}

		if recvErr != nil {
			if h.closing.Load() && errors.Is(recvErr, windows.ERROR_NO_DATA) {
				return
			}
			if errors.Is(recvErr, windows.ERROR_INSUFFICIENT_BUFFER) {
				marker := []winDivertBatchPacket{{
					ci: gopacket.CaptureInfo{Timestamp: receivedAt, CaptureLength: 0, Length: len(h.buf) + 1},
				}}
				if !h.queueBatch(marker) {
					return
				}
				continue
			}
			h.recordErr(recvErr)
			return
		}

		pkts, splitErr := splitWinDivertBatch(h.buf, h.recvLen, h.addrBuf, h.addrLen, h.snaplen, receivedAt, func(ticks int64) time.Time {
			stamp, converted := winDivertPacketTime(ticks, h.anchorTicks, h.qpcFreq, h.anchorUTC, receivedAt)
			if !converted {
				h.timestampFallbacks.Add(1)
			}
			return stamp
		})
		h.debugBatch(receivedAt, pkts, splitErr)
		if len(pkts) > 0 && !h.queueBatch(pkts) {
			return
		}
		if splitErr != nil {
			h.recordErr(splitErr)
			return
		}
	}
}

func (h *winDivertPacketHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := h.readPacket()
	if err != io.EOF {
		return data, ci, err
	}
	select {
	case err := <-h.errCh:
		return nil, ci, err
	default:
		if h.closing.Load() {
			return nil, ci, io.EOF
		}
		return nil, ci, errors.New("WinDivert packet stream ended unexpectedly")
	}
}

func (h *winDivertPacketHandle) LastPollTime() time.Time {
	ns := h.lastPollNano.Load()
	if ns <= 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

func (h *winDivertPacketHandle) drainsOnCancel() {}

func (h *winDivertPacketHandle) LinkType() layers.LinkType { return layers.LinkTypeRaw }
func (h *winDivertPacketHandle) SnapLen() int              { return h.snaplen }
func (h *winDivertPacketHandle) SetBPFFilter(string) error { return nil }
func (h *winDivertPacketHandle) Stats() (*pcap.Stats, error) {
	return nil, fmt.Errorf("WinDivert does not expose per-handle queue-drop counters")
}
func (h *winDivertPacketHandle) Close() {
	h.closeOnce.Do(func() {
		close(h.abortCh)
		h.requestStop()
		timer := time.NewTimer(2500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-h.pumpDone:
		case <-timer.C:
		}
	})
}
