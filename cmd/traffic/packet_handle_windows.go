package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/Sunmedalia/traffic/internal/session"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/windows"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
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

type winDivertPacketHandle struct {
	handle                windows.Handle
	recv, shutdown, close *windows.Proc
	once                  sync.Once
	done                  chan struct{}
	buffer                []byte
}

func openLivePacket(ctx context.Context, iface string) (packetHandle, error) {
	if !strings.HasPrefix(iface, "windivert") {
		return pcap.OpenLive(iface, captureSnapshotLength(), false, 100*time.Millisecond)
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
	recv, err := dll.FindProc("WinDivertRecv")
	if err != nil {
		dll.Release()
		return nil, err
	}
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
	value, _, callErr := open.Call(uintptr(unsafe.Pointer(bytes)), 0, 0, 1|4)
	if windows.Handle(value) == windows.InvalidHandle {
		dll.Release()
		return nil, fmt.Errorf("启动随包 WinDivert 驱动失败: %w（检查管理员权限及系统驱动策略）", callErr)
	}
	result := &winDivertPacketHandle{handle: windows.Handle(value), recv: recv, shutdown: shutdown, close: closeProc, done: make(chan struct{}), buffer: make([]byte, captureSnapshotLength())}
	go func() {
		select {
		case <-ctx.Done():
			shutdown.Call(uintptr(result.handle), 1)
		case <-result.done:
		}
	}()
	// Keep this DLL loaded for process lifetime: cancellation may still be
	// unwinding a synchronous receive when Close releases the driver handle.
	return result, nil
}
func (h *winDivertPacketHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	var received uint32
	var address [80]byte
	ok, _, err := h.recv.Call(uintptr(h.handle), uintptr(unsafe.Pointer(&h.buffer[0])), uintptr(len(h.buffer)), uintptr(unsafe.Pointer(&received)), uintptr(unsafe.Pointer(&address[0])))
	if ok == 0 {
		return nil, gopacket.CaptureInfo{}, err
	}
	if received > uint32(len(h.buffer)) {
		return nil, gopacket.CaptureInfo{}, errors.New("invalid WinDivert packet length")
	}
	// Ownership must survive the next receive and asynchronous TCP assembly.
	data := append([]byte(nil), h.buffer[:received]...)
	return data, gopacket.CaptureInfo{Timestamp: time.Now().UTC(), CaptureLength: len(data), Length: len(data)}, nil
}
func (h *winDivertPacketHandle) LinkType() layers.LinkType { return layers.LinkTypeRaw }
func (h *winDivertPacketHandle) SnapLen() int              { return int(captureSnapshotLength()) }
func (h *winDivertPacketHandle) SetBPFFilter(string) error { return nil }
func (h *winDivertPacketHandle) Stats() (*pcap.Stats, error) {
	return nil, fmt.Errorf("WinDivert does not expose per-handle queue-drop counters")
}
func (h *winDivertPacketHandle) Close() {
	h.once.Do(func() { close(h.done); h.shutdown.Call(uintptr(h.handle), 1); h.close.Call(uintptr(h.handle)) })
}
