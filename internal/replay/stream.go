package replay

import (
	"context"
	"io"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/tcpassembly"
	"golang.org/x/sync/semaphore"
)

const packetQueueBudget = 32 << 20

type streamChunk struct {
	data []byte
	seen time.Time
}

type queuedStream struct {
	ctx        context.Context
	budget     *semaphore.Weighted
	factory    *streamFactory
	launch     func()
	started    bool
	lastSeen   time.Time
	onClose    func()
	server     string
	connection string
	abort      *atomic.Bool
	processor  *HTTPProcessor
	chunks     chan streamChunk
	current    []byte
	reserved   int64
	failed     atomic.Bool
	closed     bool
	store      *Store
	observed   atomic.Int64
	latest     time.Time
}

func (s *queuedStream) Reassembled(rs []tcpassembly.Reassembly) {
	if s.closed || s.ctx.Err() != nil {
		return
	}
	if s.abort != nil && s.abort.Load() {
		s.closeInput()
		return
	}
	for _, r := range rs {
		if r.Skip != 0 {
			s.failed.Store(true)
			s.store.gap("pcap", s.connection, "tcp_sequence_gap", "events", 1)
			// Stop this direction at a gap rather than interpreting shifted bytes.
			if r.Skip > 0 {
				s.abortConnection()
				s.closeInput()
				return
			}
		}
		if len(r.Bytes) == 0 {
			continue
		}
		if !s.started && !s.start() {
			return
		}
		n := int64(len(r.Bytes))
		// The input is already on disk. Wait for the parser to consume data
		// instead of losing a TCP direction when the reader gets ahead.
		if s.budget.Acquire(s.ctx, n) != nil {
			return
		}
		b := append([]byte(nil), r.Bytes...)
		select {
		case s.chunks <- streamChunk{data: b, seen: r.Seen}:
		case <-s.ctx.Done():
			s.budget.Release(n)
			return
		}
	}
}

// start launches the parser for this direction's first payload. Without a free
// parser the direction is dropped and reported rather than blocking the reader.
func (s *queuedStream) start() bool {
	if s.factory != nil && !s.factory.takeParser() {
		s.factory.rejected++
		s.failed.Store(true)
		s.closeInput()
		return false
	}
	s.started = true
	if s.chunks == nil {
		s.chunks = make(chan streamChunk, 256)
	}
	if s.launch != nil {
		s.launch()
	}
	return true
}

func (s *queuedStream) ReassemblyComplete() {
	s.closeInput()
	if s.onClose != nil {
		s.onClose()
		s.onClose = nil
	}
}
func (s *queuedStream) closeInput() {
	if !s.closed {
		s.closed = true
		if s.chunks != nil {
			close(s.chunks)
		}
	}
}
func (s *queuedStream) Read(b []byte) (int, error) {
	for len(s.current) == 0 {
		var ok bool
		var chunk streamChunk
		chunk, ok = <-s.chunks
		if !ok {
			return 0, io.EOF
		}
		s.current = chunk.data
		s.reserved = int64(len(chunk.data))
		if !chunk.seen.IsZero() {
			s.observed.Store(chunk.seen.UnixNano())
			if chunk.seen.After(s.latest) {
				s.latest = chunk.seen.UTC()
			}
		}
	}
	n := copy(b, s.current)
	s.current = s.current[n:]
	if len(s.current) == 0 {
		s.current = nil
		s.budget.Release(s.reserved)
	}
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

func (s *queuedStream) Aborted() bool { return s.abort != nil && s.abort.Load() }
func (s *queuedStream) abortConnection() {
	if s.abort != nil {
		s.abort.Store(true)
	}
	if s.processor != nil {
		s.processor.invalidate(s.connection, "tcp_stream_gap")
	}
}
