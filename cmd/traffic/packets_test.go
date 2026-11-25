package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestPacketCaptureProgressPublishesBoundsAndAggregatesGaps(t *testing.T) {
	s := &Store{dir: t.TempDir()}
	start := time.Now().UTC()
	p := packetCaptureProgress{}
	for _, stamp := range []time.Time{start.Add(time.Second), start, start.Add(2 * time.Second)} {
		p.addCaptured(stamp)
	}
	p.publish(s)
	p.addCaptured(start.Add(time.Second))
	p.publish(s)
	p.publish(s)

	p.truncated, p.driverOverflow = 8, 3
	p.reportGaps(s, "lo")
	p.reportGaps(s, "lo")
	stats := snapshotStats(s)
	if stats.Packets != 4 || stats.FirstPacketAt != start || stats.LastPacketAt != start.Add(2*time.Second) ||
		stats.GapCounts["pcap/snapshot_truncated/packets"] != 8 ||
		stats.GapCounts["pcap/driver_buffer_overflow/packets"] != 3 || s.gapEvents != 2 {
		t.Fatalf("packet progress: %+v", stats)
	}
}

func TestPacketRingWindowsDeviceAndLargeFrame(t *testing.T) {
	dir := t.TempDir()
	device := `\Device\NPF_{010DBF10-606E-4FF7-9B78-CEEB459A8EB8}`
	ring := packetRing{dir: dir, iface: device, link: uint32(layers.LinkTypeNull), snaplen: uint32(captureSnapshotLength())}
	// CentOS 7 loopback produces Ethernet frames of 65549 bytes. Npcap's
	// 65539-byte loopback frames fit inside this same capture budget.
	data := bytes.Repeat([]byte{1}, 65549)
	if len(data) > int(captureSnapshotLength()) {
		t.Fatal("live capture would truncate the full-size loopback frame")
	}
	if err := ring.write(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}, data); err != nil {
		t.Fatal(err)
	}
	if err := ring.close(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("device filename: %v %v", files, err)
	}
	file, err := os.Open(filepath.Join(dir, files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := reader.ReadPacketData()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("large frame was lost or truncated: %d bytes, %v", len(got), err)
	}
}

func TestPacketRingFlushesBufferedTailAtRotationAndClose(t *testing.T) {
	dir := t.TempDir()
	ring := packetRing{dir: dir, iface: "lo", link: uint32(layers.LinkTypeEthernet), snaplen: uint32(captureSnapshotLength())}
	payload := []byte("small buffered packet")
	info := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(payload), Length: len(payload)}
	if err := ring.write(info, payload); err != nil {
		t.Fatal(err)
	}
	buffer := ring.buffer
	ring.size = 64 << 20
	if err := ring.write(info, payload); err != nil {
		t.Fatal(err)
	}
	if ring.buffer != buffer {
		t.Fatal("rotation replaced the packet buffer")
	}
	if err := ring.close(); err != nil {
		t.Fatal(err)
	}
	if err := ring.close(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 2 {
		t.Fatal("rotation missing", files, err)
	}
	for _, name := range files {
		file, err := os.Open(filepath.Join(dir, name.Name()))
		if err != nil {
			t.Fatal(err)
		}
		reader, err := pcapgo.NewReader(file)
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		data, _, err := reader.ReadPacketData()
		file.Close()
		if err != nil || !bytes.Equal(data, payload) {
			t.Fatal("buffered packet lost at ring boundary", name.Name(), data, err)
		}
	}
}

func TestPacketSegmentsNeverOverwriteEarlierEvidence(t *testing.T) {
	dir := t.TempDir()
	ring := packetRing{dir: dir, iface: "lo", link: uint32(layers.LinkTypeEthernet), snaplen: 65535}
	data := []byte("retained evidence")
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}
	for i := 0; i < 20; i++ {
		ring.size = 64 << 20
		if err := ring.write(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := ring.close(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 20 {
		t.Fatal("segments overwritten", len(files), err)
	}
}

func TestPacketWriterPersistsInOrderOffCaptureLoop(t *testing.T) {
	dir := t.TempDir()
	s := &Store{}
	ring := &packetRing{dir: dir, iface: "lo", link: uint32(layers.LinkTypeEthernet), snaplen: uint32(captureSnapshotLength())}
	w := newPacketWriter(s, "lo", ring)
	if cap(w.queue) != 32768 {
		t.Fatalf("packet queue capacity = %d, want 32768", cap(w.queue))
	}
	for i := 0; i < 100; i++ {
		data := []byte{byte(i), 1, 2, 3}
		if accepted, err := w.write(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}, data); err != nil || !accepted {
			t.Fatalf("accepted=%v err=%v", accepted, err)
		}
	}
	if err := w.close(); err != nil {
		t.Fatal(err)
	}
	if err := w.close(); err != nil {
		t.Fatal("second close", err)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatal("segments", files)
	}
	file, err := os.Open(filepath.Join(dir, files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		got, _, err := reader.ReadPacketData()
		if err != nil || got[0] != byte(i) {
			t.Fatal("packet lost or reordered", i, err)
		}
	}
	if w.pending.Load() != 0 || s.stats.GapCounts != nil {
		t.Fatal("unexpected pending bytes or gaps", w.pending.Load(), s.stats.GapCounts)
	}
}

type blockedPacketSegment struct {
	bytes.Buffer
	started, unblock  chan struct{}
	syncErr, closeErr error
}

func (f *blockedPacketSegment) Sync() error {
	close(f.started)
	<-f.unblock
	return f.syncErr
}

func (f *blockedPacketSegment) Close() error { return f.closeErr }

func TestPacketWriterRotatesWhileOldSegmentSyncsAndJoinsCloseErrors(t *testing.T) {
	dir := t.TempDir()
	old := &blockedPacketSegment{
		started: make(chan struct{}), unblock: make(chan struct{}),
		syncErr: errors.New("segment sync failed"), closeErr: errors.New("segment close failed"),
	}
	buffer := bufio.NewWriter(old)
	ring := &packetRing{
		dir: dir, iface: "lo", link: uint32(layers.LinkTypeEthernet), snaplen: 65535,
		file: old, buffer: buffer, writer: pcapgo.NewWriterNanos(buffer), size: 64 << 20, index: 1,
	}
	w := newPacketWriter(&Store{}, "lo", ring)
	var release sync.Once
	unblock := func() { close(old.unblock) }
	t.Cleanup(func() {
		release.Do(unblock)
		_ = w.close()
	})

	packet := []byte{1, 2, 3, 4}
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(packet), Length: len(packet)}
	if accepted, err := w.write(ci, packet); !accepted || err != nil {
		t.Fatalf("write accepted=%t err=%v", accepted, err)
	}
	select {
	case <-old.started:
	case <-time.After(2 * time.Second):
		t.Fatal("retired segment did not start syncing")
	}

	path := filepath.Join(dir, "lo-000000000002.pcap")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rotation stalled on the previous file's Sync")
		}
		time.Sleep(time.Millisecond)
	}

	closed := make(chan error, 1)
	go func() { closed <- w.close() }()
	select {
	case err := <-closed:
		t.Fatalf("close returned before the retired segment finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	release.Do(unblock)
	select {
	case err := <-closed:
		if !errors.Is(err, old.syncErr) || !errors.Is(err, old.closeErr) {
			t.Fatalf("close did not report both segment errors: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not finish")
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := reader.ReadPacketData(); err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("rotated segment packet = %v, err=%v", got, err)
	}
}

func TestPacketWriterShedsWithExplicitGapWhenQueueFull(t *testing.T) {
	s := &Store{}
	// Do not start the consumer yet, so the two-slot queue fills.
	ring := &packetRing{dir: t.TempDir(), iface: "eth0", link: uint32(layers.LinkTypeEthernet), snaplen: uint32(captureSnapshotLength())}
	w := &packetWriter{store: s, iface: "eth0", ring: ring, queue: make(chan packetWriteItem, 2), done: make(chan struct{})}
	data := make([]byte, 64)
	info := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}
	for i := 0; i < 5; i++ {
		if _, err := w.write(info, data); err != nil {
			t.Fatal(err)
		}
	}
	if w.dropped.Load() != 3 {
		t.Fatal("queue overflow was not counted", w.dropped.Load())
	}
	w.pending.Store(packetWriteQueueBytes)
	if accepted, err := w.write(info, data); err != nil || accepted || w.dropped.Load() != 4 {
		t.Fatal("byte budget was not enforced", accepted, w.dropped.Load())
	}
	w.pending.Store(int64(2 * len(data)))
	go w.run()
	if err := w.close(); err != nil {
		t.Fatal(err)
	}
	if got := s.stats.GapCounts["pcap/write_queue_overflow/packets"]; got != 4 {
		t.Fatal("shed packets not reported as a gap", s.stats.GapCounts)
	}
}

func TestPacketWriterReportsWriteFailure(t *testing.T) {
	s := &Store{}
	ring := &packetRing{dir: filepath.Join(t.TempDir(), "missing"), iface: "eth0", link: uint32(layers.LinkTypeEthernet), snaplen: uint32(captureSnapshotLength())}
	w := newPacketWriter(s, "eth0", ring)
	data := []byte("x")
	_, _ = w.write(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: 1, Length: 1}, data)
	deadline := time.Now().Add(time.Second)
	for w.failure() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if w.failure() == nil {
		t.Fatal("write failure not surfaced to the capture loop")
	}
	if _, err := w.write(gopacket.CaptureInfo{}, data); err == nil {
		t.Fatal("write accepted after failure")
	}
	if err := w.close(); err == nil {
		t.Fatal("close hid the write failure")
	}
}

func TestWaitWithinBoundsShutdown(t *testing.T) {
	if !waitWithin(func() {}, time.Second) {
		t.Fatal("fast stop reported as timeout")
	}
	release := make(chan struct{})
	defer close(release)
	started := time.Now()
	if waitWithin(func() { <-release }, 20*time.Millisecond) {
		t.Fatal("hung stop reported as complete")
	}
	if time.Since(started) > time.Second {
		t.Fatal("stop budget not enforced")
	}
}
