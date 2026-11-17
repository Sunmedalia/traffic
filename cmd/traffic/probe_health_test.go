package main

import (
	"github.com/Sunmedalia/traffic/internal/session"
	"testing"
)

func TestProbeFailureImmediatelyInvalidatesAttachedState(t *testing.T) {
	s := &Store{stats: Stats{TLS: "attached", Targets: []session.Target{{ID: "10:old", State: "attached"}, {ID: "20:new", State: "attached"}}}}
	s.setTLSTargetsState(map[string]bool{"10:old": true}, "unavailable")
	if s.stats.TLS != "partial" {
		t.Fatal("failure left attached state", s.stats)
	}
	s.setTLSTargetsState(map[string]bool{"20:retired": true}, "unavailable")
	if s.stats.Targets[1].State != "attached" {
		t.Fatal("stale identity changed replacement worker")
	}
	s.setTLSTargetsState(map[string]bool{"20:new": true}, "unavailable")
	if s.stats.TLS != "unavailable" {
		t.Fatal(s.stats.TLS)
	}
	s.setTLSTargetsState(map[string]bool{"10:old": true}, "starting")
	if s.stats.TLS == "attached" {
		t.Fatal("reattaching target is not ready")
	}
	s.setTLSTargetsState(map[string]bool{"10:old": true, "20:new": true}, "attached")
	if s.stats.TLS != "attached" {
		t.Fatal("reattach did not recover", s.stats)
	}
}
func TestTransportFailureReportedBeforeQueuedMessagesDrain(t *testing.T) {
	before := probeTransportBytes.Load()
	reader := newFakeProbeReader()
	for i := 0; i < 6; i++ {
		reader.messages <- make([]byte, 2<<20)
	}
	failures := make(chan error, 1)
	tr := startProbeTransport(reader, func(err error) { failures <- err })
	awaitProbeDone(t, tr)
	if len(failures) != 1 || tr.pending.Load() == 0 {
		t.Fatal("failure was delayed until parsing drained")
	}
	s := &Store{}
	stop := s.observeProbeTransport("probe", 1, tr)
	stop()
	stats := s.stats.ProbeTransports["probe"]
	if stats.Overflows != 1 || !stats.Ended || stats.LastError == "" || stats.PendingBytes != 0 || stats.ReceivedMessages == 0 {
		t.Fatal("lost terminal transport diagnostics", stats)
	}
	if probeTransportBytes.Load() != before {
		t.Fatal("transport leaked memory budget")
	}
}
