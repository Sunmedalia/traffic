//go:build !windows

package main

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPCAPBufferFlagIsBounded(t *testing.T) {
	old := pcapBufferMiB
	defer func() { pcapBufferMiB = old }()
	for _, value := range []string{"1", "1025"} {
		err := run([]string{"capture", "--no-tls", "--pcap-buffer-mib", value, "--output", t.TempDir() + "/session"})
		if err == nil || !strings.Contains(err.Error(), "--pcap-buffer-mib") {
			t.Fatalf("--pcap-buffer-mib %s: %v", value, err)
		}
	}
}

// The configured buffer must not stop libpcap from activating and delivering
// packets; this needs CAP_NET_RAW and is skipped without it.
func TestOpenPCAPLiveWithConfiguredBufferCapturesLoopback(t *testing.T) {
	old := pcapBufferMiB
	pcapBufferMiB = 8
	defer func() { pcapBufferMiB = old }()
	handle, err := openPCAPLive("lo")
	if err != nil {
		t.Skipf("loopback capture unavailable: %v", err)
	}
	defer handle.Close()
	if handle.bufferFallback() != nil {
		t.Fatalf("8 MiB buffer refused: %v", handle.bufferFallback())
	}
	if handle.SnapLen() != int(captureSnapshotLength()) {
		t.Fatalf("snaplen = %d", handle.SnapLen())
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if err := handle.SetBPFFilter("tcp port " + itoa(port)); err != nil {
		t.Fatal(err)
	}
	go func() {
		if conn, err := net.Dial("tcp", listener.Addr().String()); err == nil {
			conn.Close()
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if data, _, err := handle.ReadPacketData(); err == nil && len(data) > 0 {
			return
		}
	}
	t.Fatal("no loopback packet captured")
}

func itoa(n int) string { return strconv.Itoa(n) }
