package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestPacketRingWindowsDeviceAndLargeFrame(t *testing.T) {
	dir := t.TempDir()
	device := `\Device\NPF_{010DBF10-606E-4FF7-9B78-CEEB459A8EB8}`
	ring := packetRing{dir: dir, iface: device, link: layers.LinkTypeNull, snaplen: uint32(captureSnapshotLength())}
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
	ring := packetRing{dir: dir, iface: "lo", link: layers.LinkTypeEthernet, snaplen: uint32(captureSnapshotLength())}
	payload := []byte("small buffered packet")
	info := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(payload), Length: len(payload)}
	if err := ring.write(info, payload); err != nil {
		t.Fatal(err)
	}
	ring.size = 64 << 20
	if err := ring.write(info, payload); err != nil {
		t.Fatal(err)
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
	ring := packetRing{dir: dir, iface: "lo", link: layers.LinkTypeEthernet, snaplen: 65535}
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
