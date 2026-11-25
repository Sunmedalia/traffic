package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sunmedalia/traffic/internal/packetio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type packetRing struct {
	dir, iface string
	file       *evidenceFile
	buffer     *bufio.Writer
	writer     *pcapgo.Writer
	size       int64
	index      int
	link       uint32
	snaplen    uint32
}

func (r *packetRing) write(ci gopacket.CaptureInfo, b []byte) error {
	if r.file == nil || r.size+int64(len(b))+16 > 64<<20 {
		if r.file != nil {
			if err := r.closeSegment(); err != nil {
				return err
			}
		}
		r.index++
		name := filepath.Join(r.dir, fmt.Sprintf("%s-%012d.pcap", packetInterfaceName(r.iface), r.index))
		f, e := os.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		r.file = newEvidenceFile(f)
		if r.buffer == nil {
			r.buffer = bufio.NewWriterSize(r.file, 256<<10)
			r.writer = pcapgo.NewWriterNanos(r.buffer)
		} else {
			r.buffer.Reset(r.file)
		}
		if e = packetio.WriteHeader(r.buffer, r.snaplen, r.link); e != nil {
			return e
		}
		r.size = 24
	}
	e := r.writer.WritePacket(ci, b)
	r.size += int64(len(b)) + 16
	return e
}

func (r *packetRing) close() error {
	err := r.closeSegment()
	r.buffer, r.writer = nil, nil
	return err
}

func (r *packetRing) closeSegment() error {
	if r.file == nil {
		return nil
	}
	err := r.buffer.Flush()
	err = errors.Join(err, r.file.Sync(), r.file.Close())
	r.file = nil
	return err
}

const packetWriteQueueBytes = 16 << 20
const packetWriteQueueItems = 8192

type packetWriteItem struct {
	ci   gopacket.CaptureInfo
	data []byte
}

// packetWriter moves PCAP encoding, buffered writes, periodic flushes and the
// rotation fsync off the capture loop. Previously a slow disk or the Sync at
// each 64 MiB rotation stalled ReadPacketData, so the kernel ring dropped
// packets without attribution. Live capture now sheds into an explicit
// pcap/write_queue_overflow gap once the bounded queue is full. Offline import
// uses syncPacketSink instead because it can wait without losing input.
type packetWriter struct {
	store    *Store
	iface    string
	ring     *packetRing
	queue    chan packetWriteItem
	done     chan struct{}
	pending  atomic.Int64
	dropped  atomic.Uint64
	failed   atomic.Bool
	reported uint64
	mu       sync.Mutex
	err      error
	closed   bool
}

type packetSink interface {
	write(gopacket.CaptureInfo, []byte) (bool, error)
	failure() error
	close() error
}

// syncPacketSink keeps each PCAPNG interface separate. Import can wait for
// disk without discarding input. The reader bounds the number of interfaces.
type syncPacketSink struct {
	dir   string
	input *offlinePacketHandle
	rings map[int]*packetRing
}

func (w *syncPacketSink) write(ci gopacket.CaptureInfo, data []byte) (bool, error) {
	ring := w.rings[ci.InterfaceIndex]
	if ring == nil {
		name := "offline"
		if w.input.IsPCAPNG() {
			name = fmt.Sprintf("offline-%d", ci.InterfaceIndex)
		}
		ring = &packetRing{dir: w.dir, iface: name, link: w.input.Link, snaplen: w.input.Snap}
		w.rings[ci.InterfaceIndex] = ring
	}
	err := ring.write(ci, data)
	return err == nil, err
}
func (w *syncPacketSink) failure() error { return nil }
func (w *syncPacketSink) close() error {
	var err error
	for _, ring := range w.rings {
		err = errors.Join(err, ring.close())
	}
	return err
}

func newPacketWriter(s *Store, iface string, ring *packetRing) *packetWriter {
	w := &packetWriter{store: s, iface: iface, ring: ring, queue: make(chan packetWriteItem, packetWriteQueueItems), done: make(chan struct{})}
	go w.run()
	return w
}

func (w *packetWriter) failure() error {
	if !w.failed.Load() {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *packetWriter) write(ci gopacket.CaptureInfo, data []byte) (bool, error) {
	if err := w.failure(); err != nil {
		return false, err
	}
	n := int64(len(data))
	item := packetWriteItem{ci: ci, data: data}
	if w.pending.Load()+n > packetWriteQueueBytes {
		w.dropped.Add(1)
		return false, nil
	}
	w.pending.Add(n)
	select {
	case w.queue <- item:
		return true, nil
	default:
		w.pending.Add(-n)
		w.dropped.Add(1)
		return false, nil
	}
}

// reportDrops publishes shed packets as one aggregated gap per interval so an
// overloaded disk does not also flood the gap journal with one line per packet.
func (w *packetWriter) reportDrops() {
	total := w.dropped.Load()
	if delta := total - w.reported; delta > 0 {
		w.reported = total
		w.store.gap("pcap", w.iface, "write_queue_overflow", "packets", delta)
	}
}

func (w *packetWriter) run() {
	defer close(w.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	fail := func(err error) {
		w.mu.Lock()
		if w.err == nil {
			w.err = err
			w.failed.Store(true)
		}
		w.mu.Unlock()
	}
	for {
		select {
		case item, ok := <-w.queue:
			if !ok {
				w.reportDrops()
				if err := w.ring.close(); err != nil {
					fail(err)
				}
				return
			}
			w.pending.Add(-int64(len(item.data)))
			if err := w.ring.write(item.ci, item.data); err != nil {
				fail(err)
				// Keep draining so the capture loop never blocks on a dead writer.
				for item := range w.queue {
					w.pending.Add(-int64(len(item.data)))
				}
				_ = w.ring.close()
				return
			}
		case <-ticker.C:
			w.reportDrops()
			if w.ring.file != nil {
				if err := w.ring.buffer.Flush(); err != nil {
					fail(err)
				}
			}
		}
	}
}

// close drains queued packets, flushes, syncs and closes the current segment.
func (w *packetWriter) close() error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
	w.mu.Unlock()
	<-w.done
	return w.failure()
}

func capturePackets(ctx context.Context, s *Store, p *eventRecorder, iface, filter, input string) error {
	var h packetHandle
	var e error
	var offline *offlinePacketHandle
	if input != "" {
		offline, e = openOfflinePacket(input)
		h = offline
	} else {
		h, e = openLivePacket(ctx, iface)
	}
	if e != nil {
		return e
	}
	defer h.Close()
	if source, ok := h.(interface{ bufferFallback() error }); ok {
		if err := source.bufferFallback(); err != nil {
			s.gap("pcap", iface, "capture_buffer_fallback", "sources", 1)
			s.problem(err)
		}
	}
	reportTimestampFallbacks := func() {
		if source, ok := h.(interface{ takeTimestampFallbacks() uint64 }); ok {
			if count := source.takeTimestampFallbacks(); count > 0 {
				s.gap("pcap", iface, "timestamp_fallback", "packets", count)
			}
		}
	}
	defer reportTimestampFallbacks()
	if input == "" {
		defer func() {
			if stats, err := h.Stats(); err == nil {
				s.recordPacketDrops(iface, uint64(stats.PacketsDropped+stats.PacketsIfDropped))
			}
		}()
	}
	if e = h.SetBPFFilter(filter); e != nil {
		return e
	}
	packetDir := filepath.Join(s.dir, "packets")
	if err := os.MkdirAll(packetDir, 0700); err != nil {
		return err
	}
	if input == "" {
		if _, err := h.Stats(); err != nil {
			s.gap("pcap", iface, "drop_counter_unavailable", "sources", 1)
		}
		s.packetSourceState(iface, "ready")
		defer s.packetSourceState(iface, "stopped")
	}
	var writer packetSink
	if offline != nil {
		writer = &syncPacketSink{dir: packetDir, input: offline, rings: make(map[int]*packetRing)}
	} else {
		ring := &packetRing{dir: packetDir, iface: iface, link: uint32(h.LinkType()), snaplen: uint32(h.SnapLen())}
		writer = newPacketWriter(s, iface, ring)
	}
	defer func() {
		if err := writer.close(); err != nil {
			s.fail(fmt.Errorf("close packet evidence: %w", err))
		}
	}()
	last := time.Now()
	if input != "" {
		if err := checkDisk(s); err != nil {
			return err
		}
	} else {
		s.notePacketPoll(time.Now().UTC())
	}
	var importedBytes int64
	_, drainsOnCancel := h.(interface{ drainsOnCancel() })
	var drainDeadline time.Time
	for {
		if ctx.Err() != nil {
			if !drainsOnCancel {
				return nil
			}
			if drainDeadline.IsZero() {
				drainDeadline = time.Now().Add(2500 * time.Millisecond)
			}
			if time.Now().After(drainDeadline) {
				return errors.New("WinDivert packet drain timed out")
			}
		}
		data, ci, e := h.ReadPacketData()
		if input == "" {
			if pt, ok := h.(pollTimestamper); ok {
				s.notePacketPoll(pt.LastPollTime())
			} else {
				s.notePacketPoll(time.Now().UTC())
			}
		}
		if e == pcap.NextErrorTimeoutExpired {
			if err := writer.failure(); err != nil {
				return err
			}
			continue
		}
		if e != nil {
			if (input != "" || drainsOnCancel && ctx.Err() != nil) && errors.Is(e, io.EOF) {
				return nil
			}
			return e
		}
		if len(data) == 0 && ci.CaptureLength == 0 && ci.Length > 0 {
			s.gap("pcap", iface, "driver_buffer_overflow", "packets", 1)
			continue
		}
		accepted, writeErr := writer.write(ci, data)
		if writeErr != nil {
			return writeErr
		}
		if input != "" {
			// checkDisk walks the session directory; checking every 1 MiB
			// made large imports quadratic in the number of segments.
			importedBytes += int64(len(data)) + 16
			if importedBytes >= 16<<20 || time.Since(last) > time.Second {
				if e = checkDisk(s); e != nil {
					return e
				}
				importedBytes = 0
				last = time.Now()
			}
		}
		if accepted {
			s.notePacketCaptured(ci.Timestamp)
		}
		if ci.CaptureLength < ci.Length {
			s.gap("pcap", iface, "snapshot_truncated", "packets", 1)
		}
		if input == "" && time.Since(last) > time.Second {
			reportTimestampFallbacks()
			if st, e := h.Stats(); e == nil {
				s.recordPacketDrops(iface, uint64(st.PacketsDropped+st.PacketsIfDropped))
			}
			last = time.Now()
		}
	}
}

func (s *Store) packetSourceState(iface, state string) {
	s.mu.Lock()
	if s.stats.PacketInterfaces == nil {
		s.stats.PacketInterfaces = map[string]string{}
	}
	s.stats.PacketInterfaces[iface] = state
	ready := true
	for _, value := range s.stats.PacketInterfaces {
		ready = ready && value == "ready"
	}
	if ready && s.stats.State == "starting" {
		s.stats.State = "running"
	}
	s.mu.Unlock()
	s.report()
}
