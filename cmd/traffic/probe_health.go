package main

import (
	"github.com/Sunmedalia/traffic/internal/session"
	"time"
)

func tlsTargetsState(targets []session.Target) string {
	if len(targets) == 0 {
		return "no-targets"
	}
	attached, unavailable := 0, 0
	for _, target := range targets {
		if target.State == "attached" {
			attached++
		}
		if target.State == "unavailable" {
			unavailable++
		}
	}
	if attached == len(targets) {
		return "attached"
	}
	if attached > 0 {
		return "partial"
	}
	if unavailable > 0 {
		return "unavailable"
	}
	return "starting"
}

// Apply state transitions immediately, rather than leaving an old attached
// status visible until the next discovery pass. Match process start identities
// so a retired worker cannot overwrite the state of a reused PID.
func (s *Store) setTLSTargetsState(identities map[string]bool, state string) {
	s.mu.Lock()
	for i := range s.stats.Targets {
		if identities[s.stats.Targets[i].ID] {
			s.stats.Targets[i].State = state
		}
	}
	s.stats.TLS = tlsTargetsState(s.stats.Targets)
	s.mu.Unlock()
}

func (s *Store) observeProbeTransport(key string, generation uint64, t *probeTransport) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	sample := func() {
		value := session.ProbeTransportStats{Generation: generation, ReceivedMessages: t.receivedMessages.Load(), ReceivedBytes: t.receivedBytes.Load(), DequeuedMessages: t.dequeuedMessages.Load(), DequeuedBytes: t.dequeuedBytes.Load(), PendingBytes: t.pending.Load(), QueuedMessages: len(t.queue), HighWaterBytes: t.highWater.Load(), Overflows: t.overflows.Load()}
		select {
		case <-t.done:
			value.Ended = true
			if t.err != nil {
				value.LastError = t.err.Error()
			}
		default:
		}
		s.mu.Lock()
		if s.stats.ProbeTransports == nil {
			s.stats.ProbeTransports = map[string]session.ProbeTransportStats{}
		}
		if _, exists := s.stats.ProbeTransports[key]; exists || len(s.stats.ProbeTransports) < 1024 {
			s.stats.ProbeTransports[key] = value
		}
		s.mu.Unlock()
	}
	sample()
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sample()
			}
		}
	}()
	return func() { close(stop); <-done; t.close(); sample() }
}
