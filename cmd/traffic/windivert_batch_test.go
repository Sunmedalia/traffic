package main

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

func TestSplitWinDivertBatchIPv4AndIPv6WithQPCTimestampsAndSnaplen(t *testing.T) {
	p1 := make([]byte, 40)
	p1[0] = 0x45
	binary.BigEndian.PutUint16(p1[2:4], uint16(len(p1)))
	p1[39] = 0xaa

	p2 := make([]byte, 60)
	p2[0] = 0x60
	binary.BigEndian.PutUint16(p2[4:6], uint16(len(p2)-40))
	p2[59] = 0xbb

	p3 := bytes.Repeat([]byte{0xcc}, 120)
	p3[0] = 0x45
	binary.BigEndian.PutUint16(p3[2:4], uint16(len(p3)))

	raw := append(append(append([]byte{}, p1...), p2...), p3...)
	addrBuf := make([]byte, 3*winDivertAddrSize)
	anchor := time.Date(2026, 11, 18, 5, 0, 0, 0, time.UTC)
	const freq = 10_000_000 // 10 MHz QPC
	const anchorTicks = 1_000_000_000
	binary.LittleEndian.PutUint64(addrBuf[0:8], uint64(anchorTicks+10_000))         // +1ms
	binary.LittleEndian.PutUint64(addrBuf[80:88], uint64(anchorTicks+25_000))       // +2.5ms
	binary.LittleEndian.PutUint64(addrBuf[160:168], uint64(anchorTicks+10_000_000)) // +1s

	got, err := splitWinDivertBatch(raw, uint32(len(raw)), addrBuf, uint32(len(addrBuf)), 80, func(ticks int64) time.Time {
		return qpcTicksToUTC(ticks, anchorTicks, freq, anchor)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(got))
	}
	if !bytes.Equal(got[0].data, p1) || !got[0].ci.Timestamp.Equal(anchor.Add(time.Millisecond)) {
		t.Fatalf("packet 0 mismatch: len=%d ts=%v", len(got[0].data), got[0].ci.Timestamp)
	}
	if !bytes.Equal(got[1].data, p2) || !got[1].ci.Timestamp.Equal(anchor.Add(2500*time.Microsecond)) {
		t.Fatalf("packet 1 mismatch: len=%d ts=%v", len(got[1].data), got[1].ci.Timestamp)
	}
	if len(got[2].data) != 80 || got[2].ci.CaptureLength != 80 || got[2].ci.Length != 120 || !got[2].ci.Timestamp.Equal(anchor.Add(time.Second)) {
		t.Fatalf("packet 2 snaplen mismatch: %+v", got[2].ci)
	}
}

func TestSplitWinDivertBatchRejectsCorruptHeaders(t *testing.T) {
	addrBuf := make([]byte, 2*winDivertAddrSize)
	corrupt := make([]byte, 30)
	corrupt[0] = 0x45
	binary.BigEndian.PutUint16(corrupt[2:4], 100) // exceeds remaining batch length
	if _, err := splitWinDivertBatch(corrupt, uint32(len(corrupt)), addrBuf, uint32(len(addrBuf)), 65535, nil); err == nil {
		t.Fatal("accepted corrupt IPv4 total length in batch")
	}
}

func TestIISBindingPortScopeAndProbeExitAccounting(t *testing.T) {
	xmlConfig := []byte(`<configuration><system.applicationHost><sites><site><bindings>
<binding protocol="http" bindingInformation="*:80:" />
<binding protocol="https" bindingInformation="*:443:site" />
</bindings></site></sites></system.applicationHost></configuration>`)
	all := parseIISBindingPorts(xmlConfig, "http", "https")
	httpsOnly := parseIISBindingPorts(xmlConfig, "https")
	if !reflect.DeepEqual(all, []int{80, 443}) || !reflect.DeepEqual(httpsOnly, []int{443}) {
		t.Fatalf("unexpected IIS binding ports: all=%v https=%v", all, httpsOnly)
	}
	if iisPortsMatchHTTPS(all, httpsOnly, map[int]bool{80: true}) {
		t.Fatal("plain HTTP port 80 falsely matched IIS HTTPS bindings")
	}
	if !iisPortsMatchHTTPS(all, httpsOnly, map[int]bool{80: true, 443: true}) {
		t.Fatal("mixed 80,443 failed to match IIS HTTPS bindings")
	}
	if !iisPortsMatchHTTPS(nil, nil, map[int]bool{80: true}) {
		t.Fatal("missing applicationHost.config must not block explicit IIS attach")
	}

	// P4: Hooks removed, but script/transport unload timed out.
	s := &Store{dir: t.TempDir()}
	s.stats.Started = time.Date(2026, 11, 18, 6, 0, 0, 0, time.UTC)
	s.stats.Stopped = s.stats.Started.Add(30 * time.Second)
	s.notePacketPoll(s.stats.Stopped)
	s.notePacketCaptured(s.stats.Started.Add(100 * time.Millisecond))
	recordWindowsProbeExit(s, "6092:1", true, true, false, false)
	if err := finishCaptureStateReason(s, false, false, false, "duration"); err != nil {
		t.Fatal(err)
	}
	if s.stats.StopReason != "duration" || s.stats.DrainState != "confirmed" {
		t.Fatalf("unexpected stop/drain state: %+v", s.stats)
	}
	if s.stats.GapCounts["windows-probe/runtime_unload_incomplete/shutdowns"] != 1 {
		t.Fatalf("missing runtime_unload_incomplete gap: %+v", s.stats.GapCounts)
	}
	joined := strings.Join(s.stats.IntegrityWarnings, "\n")
	if !strings.Contains(joined, "收包时间提前中断") || !strings.Contains(joined, "未完全从目标进程卸载") {
		t.Fatalf("expected stall and incomplete-unload warnings, got: %s", joined)
	}

	// Unrestored hooks must downgrade DrainState to unverified.
	s2 := &Store{dir: t.TempDir()}
	recordWindowsProbeExit(s2, "6092:2", true, false, false, false)
	_ = finishCaptureStateReason(s2, false, false, false, "signal")
	if s2.stats.StopReason != "signal" || s2.stats.DrainState != "unverified" {
		t.Fatalf("unrestored hooks did not force unverified drain: %+v", s2.stats)
	}
	if s2.stats.GapCounts["windows-probe/hooks_not_restored/shutdowns"] != 1 {
		t.Fatalf("missing hooks_not_restored gap: %+v", s2.stats.GapCounts)
	}

	// HTTP-only IIS capture without probes attached should confirm drain cleanly.
	s3 := &Store{dir: t.TempDir(), stats: session.Stats{TLS: "http-only"}}
	_ = finishCaptureStateReason(s3, false, false, false, "duration")
	if s3.stats.DrainState != "confirmed" {
		t.Fatalf("http-only target without probes should confirm drain: %+v", s3.stats)
	}
}

func TestWinDivertBatchChecksEveryAddressAndAllPacketBytes(t *testing.T) {
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	joined := append(append([]byte(nil), packet...), packet...)
	meta := make([]byte, 3*winDivertAddrSize)
	for _, tc := range []struct {
		name         string
		raw          []byte
		addressBytes uint32
	}{
		{"uninitialized address length", packet, 0},
		{"partial address record", packet, winDivertAddrSize + 1},
		{"address length exceeds buffer", packet, 4 * winDivertAddrSize},
		{"stale extra address", joined, 3 * winDivertAddrSize},
		{"trailing bytes with one address", joined, winDivertAddrSize},
		{"incomplete last packet", joined[:len(joined)-1], 2 * winDivertAddrSize},
		{"packet missing despite address", nil, winDivertAddrSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitWinDivertBatch(tc.raw, uint32(len(tc.raw)), meta, tc.addressBytes, 65535, nil)
			if err == nil || len(got) != 0 {
				t.Fatalf("exposed invalid batch: got %d packets, err=%v", len(got), err)
			}
		})
	}
}

func TestWinDivertPacketTimeRejectsImplausibleQPC(t *testing.T) {
	anchor := time.Date(2026, 11, 18, 9, 44, 51, 0, time.UTC)
	const frequency int64 = 10_000_000
	const ticks = frequency * 7200
	received := anchor.Add(7 * time.Second)
	if stamp, converted := winDivertPacketTime(ticks+6*frequency, ticks, frequency, anchor, received); !converted || !stamp.Equal(anchor.Add(6*time.Second)) {
		t.Fatalf("valid QPC stamp rejected: %s, converted=%v", stamp, converted)
	}
	for _, invalid := range []int64{0, ticks - 2*frequency, ticks + 600*frequency, 1<<63 - 1} {
		stamp, converted := winDivertPacketTime(invalid, ticks, frequency, anchor, received)
		if converted || !stamp.Equal(received) {
			t.Fatalf("implausible ticks %d accepted: %s", invalid, stamp)
		}
	}
	later := anchor.Add(35 * time.Second)
	if stamp, converted := winDivertPacketTime(ticks+frequency, ticks, frequency, anchor, later); converted || !stamp.Equal(later) {
		t.Fatalf("stale QPC stamp accepted: %s", stamp)
	}
}
