package main

import (
	"encoding/json"
	"github.com/Sunmedalia/traffic/internal/session"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Stats = session.Stats

var serial atomic.Uint64

type Store struct {
	probeGapTotals map[string]uint64
	iisAttached    bool
	checkMu        sync.Mutex
	checks         map[string]captureCheck
	probeCheck     func(session.Target) captureCheck
	gapMu          sync.Mutex
	gapEvents      uint64
	targetTimes    map[string]session.Target
	packetDrops    map[string]uint64
	fatal          error
	dir            string
	mu             sync.Mutex
	stats          Stats
}

func openStore(dir string, _ bool) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, stats: Stats{DiagnosticsVersion: 1, Started: time.Now().UTC(), State: "running", TLS: "disabled"}}, nil
}
func (s *Store) report() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.targetTimes == nil {
		s.targetTimes = map[string]session.Target{}
	}
	live := map[string]session.Target{}
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
	b, _ := json.MarshalIndent(s.stats, "", "  ")
	tmp := filepath.Join(s.dir, "status.tmp")
	if os.WriteFile(tmp, b, 0600) == nil {
		os.Rename(tmp, filepath.Join(s.dir, "status.json"))
	}
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
