package replay

import (
	"github.com/Sunmedalia/traffic/internal/session"
	"strings"
	"time"
)

func (s *Store) gap(backend, connection, reason, unit string, count uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stats.GapCounts == nil {
		s.stats.GapCounts = map[string]uint64{}
	}
	s.stats.GapCounts[backend+"/"+reason+"/"+unit] += count
	if len(s.gaps) < 10000 {
		s.gaps = append(s.gaps, session.GapEvent{Time: time.Now().UTC(), Backend: backend, Connection: connection, Reason: reason, Unit: unit, Count: count})
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

// forPendingConnections enumerates the pairing state that was live when a
// source reported loss. Its callback must not call back into the processor.
func (p *HTTPProcessor) forPendingConnections(prefix string, visit func(string)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key := range p.pending {
		if strings.HasPrefix(key, prefix) {
			visit(key)
		}
	}
	for key := range p.responses {
		if strings.HasPrefix(key, prefix) {
			visit(key)
		}
	}
}
