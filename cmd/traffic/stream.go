package main

import (
	"io"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/tcpassembly"
)

var queuedBytes atomic.Int64

type queuedStream struct {
	server   string
	chunks   chan []byte
	current  []byte
	failed   atomic.Bool
	closed   bool
	store    *Store
	observed atomic.Int64
}

func (s *queuedStream) Reassembled(rs []tcpassembly.Reassembly) {
	if s.closed {
		return
	}
	for _, r := range rs {
		if !r.Seen.IsZero() {
			s.observed.Store(r.Seen.UnixNano())
		}
		if r.Skip != 0 {
			s.failed.Store(true)
		}
		if len(r.Bytes) == 0 {
			continue
		}
		n := int64(len(r.Bytes))
		if queuedBytes.Add(n) > 32<<20 {
			queuedBytes.Add(-n)
			s.drop()
			return
		}
		b := append([]byte(nil), r.Bytes...)
		select {
		case s.chunks <- b:
		default:
			queuedBytes.Add(-n)
			s.drop()
			return
		}
	}
}
func (s *queuedStream) drop() {
	s.failed.Store(true)
	s.store.mu.Lock()
	s.store.stats.QueueDropped++
	s.store.mu.Unlock()
	s.ReassemblyComplete()
}
func (s *queuedStream) ReassemblyComplete() {
	if !s.closed {
		s.closed = true
		close(s.chunks)
	}
}
func (s *queuedStream) Read(b []byte) (int, error) {
	for len(s.current) == 0 {
		var ok bool
		s.current, ok = <-s.chunks
		if !ok {
			return 0, io.EOF
		}
	}
	n := copy(b, s.current)
	s.current = s.current[n:]
	queuedBytes.Add(-int64(n))
	return n, nil
}
func (s *queuedStream) Incomplete() bool { return s.failed.Load() }

func (s *queuedStream) CaptureTime() time.Time {
	stamp := s.observed.Load()
	if stamp == 0 {
		return time.Time{}
	}
	return time.Unix(0, stamp).UTC()
}

func (s *queuedStream) LocalEndpoint() string { return s.server }
