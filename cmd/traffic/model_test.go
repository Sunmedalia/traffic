package main

import (
	"testing"

	"github.com/Sunmedalia/traffic/internal/session"
)

func TestStoreReportSnapshotIsIndependent(t *testing.T) {
	estimate := uint64(4)
	s := &Store{stats: Stats{
		ProbeTransports:    map[string]session.ProbeTransportStats{"probe": {ReceivedMessages: 1}},
		PacketInterfaces:   map[string]string{"lo": "active"},
		ProbeExits:         map[string]session.ProbeExit{"probe": {DataDrained: true}},
		GapCounts:          map[string]uint64{"gap": 2},
		Targets:            []session.Target{{ID: "target", State: "starting", Ports: []int{443}}},
		IntegrityWarnings:  []string{"warning"},
		Errors:             []string{"error"},
		TLSMissingEstimate: &estimate,
	}}
	s.packetCount.Store(3)
	first := s.reportSnapshot()
	s.mu.Lock()
	s.stats.ProbeTransports["probe"] = session.ProbeTransportStats{}
	s.stats.PacketInterfaces["lo"] = "closed"
	s.stats.ProbeExits["probe"] = session.ProbeExit{}
	s.stats.GapCounts["gap"]++
	s.stats.Targets[0].State = "attached"
	s.stats.Targets[0].Ports[0] = 8443
	s.stats.IntegrityWarnings[0] = ""
	s.stats.Errors[0] = ""
	estimate++
	s.mu.Unlock()
	next := s.reportSnapshot()

	if first.ProbeTransports["probe"].ReceivedMessages != 1 || first.PacketInterfaces["lo"] != "active" ||
		!first.ProbeExits["probe"].DataDrained || first.GapCounts["gap"] != 2 ||
		first.Targets[0].Ports[0] != 443 || first.IntegrityWarnings[0] != "warning" ||
		first.Errors[0] != "error" || *first.TLSMissingEstimate != 4 || first.Packets != 3 {
		t.Fatalf("snapshot lost its original values: %+v", first)
	}
	before, after := first.Targets[0], next.Targets[0]
	if before.State != "starting" || before.DiscoveredAt.IsZero() || before.StartingAt.IsZero() ||
		!before.ReadyAt.IsZero() || after.DiscoveredAt != before.DiscoveredAt ||
		after.StartingAt != before.StartingAt || after.ReadyAt.IsZero() {
		t.Fatalf("target timestamps before=%+v after=%+v", before, after)
	}
}
