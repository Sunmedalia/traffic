package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

// noteProbeGap records the latest running total from the IIS probe.
// The script re-emits the same counter, so adding each report would inflate the journal.
func (s *Store) noteProbeGap(target, reason, kind string, total uint64) {
	s.mu.Lock()
	if s.probeGapTotals == nil {
		s.probeGapTotals = map[string]uint64{}
	}
	key := target + "/" + reason + "/" + kind
	previous := s.probeGapTotals[key]
	if total <= previous {
		s.mu.Unlock()
		return
	}
	s.probeGapTotals[key] = total
	s.mu.Unlock()
	s.gap("iis-httpapi", target, reason+"_"+kind, "completions", total-previous)
}

// Gap units are explicit: an event or byte count is never a missing-request estimate.
// Bound the journal during prolonged overload; aggregate counters remain exact.
func (s *Store) gap(backend, connection, reason, unit string, count uint64) {
	s.gapMu.Lock()
	defer s.gapMu.Unlock()
	s.mu.Lock()
	if s.stats.GapCounts == nil {
		s.stats.GapCounts = map[string]uint64{}
	}
	s.stats.GapCounts[backend+"/"+reason+"/"+unit] += count
	if s.gapEvents >= 10000 {
		s.stats.GapJournalSuppressed++
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.gapEvents++
	if s.dir == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(s.dir, "gaps.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		err = json.NewEncoder(f).Encode(session.GapEvent{Time: time.Now().UTC(), Backend: backend, Connection: connection, Reason: reason, Count: count, Unit: unit})
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		s.fail(fmt.Errorf("save gap evidence: %w", err))
	}
}

// invalidate prevents an observed discontinuity from pairing a later response
// with a request from before the discontinuity. Caller must not hold p.mu.
func (p *HTTPProcessor) invalidate(connection, reason string) {
	p.closeHTTP2(connection, reason)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.invalidateLocked(connection, reason)
}
func (p *HTTPProcessor) invalidateLocked(connection, reason string) {
	for _, record := range p.pending[connection] {
		if err := p.s.restorePending(&record); err != nil {
			p.s.fail(err)
			continue
		}
		record.Incomplete = true
		record.IntegrityReasons = append(record.IntegrityReasons, reason)
		if err := p.s.save(record); err != nil {
			p.s.fail(err)
		}
	}
	delete(p.pending, connection)
	delete(p.requestMethods, connection)
	for _, response := range p.responses[connection] {
		p.responseBytes -= int64(len(response.raw))
		p.responseCount--
	}
	delete(p.responses, connection)
}
func (p *HTTPProcessor) finish() {
	p.finishHTTP2()
	p.mu.Lock()
	defer p.mu.Unlock()
	for key := range p.pending {
		p.invalidateLocked(key, "response_unfinished_at_stop")
	}
	for key := range p.responses {
		p.invalidateLocked(key, "orphan_response_at_stop")
	}
}

func (s *Store) recordProbeExit(target string, exit session.ProbeExit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stats.ProbeExits == nil {
		s.stats.ProbeExits = map[string]session.ProbeExit{}
	}
	if len(s.stats.ProbeExits) >= 1024 {
		for old := range s.stats.ProbeExits {
			delete(s.stats.ProbeExits, old)
			break
		}
	}
	s.stats.ProbeExits[target] = exit
}
func (p *HTTPProcessor) invalidatePrefix(prefix, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key := range p.pending {
		if strings.HasPrefix(key, prefix) {
			p.invalidateLocked(key, reason)
		}
	}
	for key := range p.responses {
		if strings.HasPrefix(key, prefix) {
			p.invalidateLocked(key, reason)
		}
	}
	for key := range p.requestMethods {
		if strings.HasPrefix(key, prefix) {
			delete(p.requestMethods, key)
		}
	}
}
