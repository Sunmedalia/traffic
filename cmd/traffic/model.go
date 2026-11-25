package main

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

type Stats = session.Stats

var serial atomic.Uint64

type Store struct {
	packetCount        atomic.Uint64
	firstPacketNano    atomic.Int64
	lastPacketNano     atomic.Int64
	lastPacketPollNano atomic.Int64
	lastTLSEventNano   atomic.Int64
	plaintextObserved  atomic.Bool
	probeGapTotals     map[string]uint64
	iisAttached        bool
	iisPlaintext       atomic.Bool
	checkMu            sync.Mutex
	checks             map[string]captureCheck
	probeCheck         func(session.Target) captureCheck
	gapMu              sync.Mutex
	gapEvents          uint64
	targetTimes        map[string]session.Target
	packetDrops        map[string]uint64
	fatal              error
	dir                string
	reportMu           sync.Mutex
	mu                 sync.Mutex
	stats              Stats

	// Data and control counts share one CAS so a recovery pair reserves both
	// budgets together across writers. Each budget fits in 32 bits.
	rawEvidencePending      atomic.Uint64
	rawEvidenceHighWater    atomic.Uint64
	rawEvidenceQueueDropped atomic.Uint64
}

func (s *Store) notePacketPoll(t time.Time) {
	if t.IsZero() {
		return
	}
	ns := t.UnixNano()
	for current := s.lastPacketPollNano.Load(); ns > current; current = s.lastPacketPollNano.Load() {
		if s.lastPacketPollNano.CompareAndSwap(current, ns) {
			return
		}
	}
}

func (s *Store) notePacketBatch(count uint64, first, last int64) {
	if count == 0 {
		return
	}
	s.packetCount.Add(count)
	for {
		cur := s.firstPacketNano.Load()
		if cur != 0 && cur <= first {
			break
		}
		if s.firstPacketNano.CompareAndSwap(cur, first) {
			break
		}
	}
	for {
		cur := s.lastPacketNano.Load()
		if cur >= last {
			break
		}
		if s.lastPacketNano.CompareAndSwap(cur, last) {
			break
		}
	}
}

func (s *Store) noteTLSEvent(t time.Time) {
	if t.IsZero() {
		t = time.Now().UTC()
	} else {
		t = t.UTC()
	}
	ns := t.UnixNano()
	for {
		cur := s.lastTLSEventNano.Load()
		if cur >= ns {
			break
		}
		if s.lastTLSEventNano.CompareAndSwap(cur, ns) {
			break
		}
	}
}

func (s *Store) rawEvidencePendingBytes() uint64 {
	return evidencePending(s.rawEvidencePending.Load()).total()
}

func (s *Store) syncAtomicStatsLocked() {
	s.stats.RawEvidencePendingBytes = s.rawEvidencePendingBytes()
	s.stats.RawEvidenceHighWaterBytes = max(s.stats.RawEvidenceHighWaterBytes, s.stats.RawEvidencePendingBytes, s.rawEvidenceHighWater.Load())
	s.stats.QueueDropped = s.rawEvidenceQueueDropped.Load()
	if n := s.packetCount.Load(); n > s.stats.Packets {
		s.stats.Packets = n
	}
	if ns := s.firstPacketNano.Load(); ns > 0 {
		t := time.Unix(0, ns).UTC()
		if s.stats.FirstPacketAt.IsZero() || t.Before(s.stats.FirstPacketAt) {
			s.stats.FirstPacketAt = t
		}
	}
	if ns := s.lastPacketNano.Load(); ns > 0 {
		t := time.Unix(0, ns).UTC()
		if t.After(s.stats.LastPacketAt) {
			s.stats.LastPacketAt = t
		}
	}
	if ns := s.lastPacketPollNano.Load(); ns > 0 {
		t := time.Unix(0, ns).UTC()
		if t.After(s.stats.LastPacketPollAt) {
			s.stats.LastPacketPollAt = t
		}
	}
	if ns := s.lastTLSEventNano.Load(); ns > 0 {
		t := time.Unix(0, ns).UTC()
		if t.After(s.stats.LastTLSEventAt) {
			s.stats.LastTLSEventAt = t
		}
	}
}

func openStore(dir string, _ bool) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, stats: Stats{DiagnosticsVersion: 1, Started: time.Now().UTC(), State: "running", TLS: "disabled"}}, nil
}
func (s *Store) report() {
	// Serialize status publications so they use the same temporary file and
	// appear in snapshot order.
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	stats := s.reportSnapshot()
	b, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return
	}
	tmp := filepath.Join(s.dir, "status.tmp")
	if os.WriteFile(tmp, b, 0600) == nil {
		os.Rename(tmp, filepath.Join(s.dir, "status.json"))
	}
}

func (s *Store) reportSnapshot() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncAtomicStatsLocked()
	live := make(map[string]session.Target, len(s.stats.Targets))
	now := time.Now().UTC()
	for i := range s.stats.Targets {
		target := &s.stats.Targets[i]
		key := target.ID + "|" + target.Library
		previous := s.targetTimes[key]
		target.DiscoveredAt, target.StartingAt, target.ReadyAt = previous.DiscoveredAt, previous.StartingAt, previous.ReadyAt
		if target.DiscoveredAt.IsZero() {
			target.DiscoveredAt = now
		}
		if target.State == "starting" && target.StartingAt.IsZero() {
			target.StartingAt = now
		}
		if target.State == "attached" && target.ReadyAt.IsZero() {
			target.ReadyAt = now
		}
		live[key] = *target
	}
	s.targetTimes = live
	return s.cloneStatsLocked()
}

func (s *Store) cloneStatsLocked() Stats {
	stats := s.stats
	stats.ProbeTransports = maps.Clone(stats.ProbeTransports)
	stats.PacketInterfaces = maps.Clone(stats.PacketInterfaces)
	stats.ProbeExits = maps.Clone(stats.ProbeExits)
	stats.GapCounts = maps.Clone(stats.GapCounts)
	stats.Targets = slices.Clone(stats.Targets)
	for i := range stats.Targets {
		stats.Targets[i].Ports = slices.Clone(stats.Targets[i].Ports)
	}
	stats.IntegrityWarnings = slices.Clone(stats.IntegrityWarnings)
	stats.Errors = slices.Clone(stats.Errors)
	if stats.TLSMissingEstimate != nil {
		estimate := *stats.TLSMissingEstimate
		stats.TLSMissingEstimate = &estimate
	}
	return stats
}
func (s *Store) problem(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.stats.Errors) < 100 {
		s.stats.Errors = append(s.stats.Errors, err.Error())
	}
}

func (s *Store) fail(err error) {
	s.problem(err)
	s.mu.Lock()
	if s.fatal == nil {
		s.fatal = err
	}
	s.mu.Unlock()
}

func (s *Store) recordPacketDrops(iface string, drops uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.packetDrops == nil {
		s.packetDrops = make(map[string]uint64)
	}
	s.packetDrops[iface] = drops
	s.stats.Dropped = 0
	for _, count := range s.packetDrops {
		s.stats.Dropped += count
	}
}
