package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var errEvidenceBackpressure = errors.New("raw evidence queue exhausted; capture stopped")

type evidenceSink interface {
	io.Writer
	Sync() error
	Close() error
}

type evidenceWriter struct {
	store       *Store
	sink        evidenceSink
	backend     string
	queue       chan []byte
	done        chan struct{}
	mu          sync.Mutex
	closeOnce   sync.Once
	timeoutOnce sync.Once
	closed      bool
	pending     int
	err         error
	timeout     time.Duration
}

func newEvidenceWriter(s *Store, sink evidenceSink, backend string) *evidenceWriter {
	// A 100 ms CPU quota interval can deliver hundreds of small probe events
	// in one burst. Keep the 4 MiB byte budget authoritative rather than
	// exhausting 128 slots while most of that budget is still unused.
	w := &evidenceWriter{store: s, sink: sink, backend: backend, queue: make(chan []byte, 2048), done: make(chan struct{}), timeout: drainTimeout}
	s.mu.Lock()
	s.stats.RawEvidenceWriters++
	s.mu.Unlock()
	go w.run()
	return w
}
func (w *evidenceWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if w.err != nil {
		err := w.err
		w.mu.Unlock()
		return 0, err
	}
	if len(data) > 4<<20 || w.pending+len(data) > 4<<20 || len(w.queue) == cap(w.queue) {
		w.err = errEvidenceBackpressure
		w.mu.Unlock()
		w.store.gap(w.backend, "", "evidence_queue_overflow", "writes", 1)
		w.store.fail(errEvidenceBackpressure)
		return 0, errEvidenceBackpressure
	}
	w.store.mu.Lock()
	if w.store.stats.RawEvidencePendingBytes+uint64(len(data)) > 32<<20 {
		w.store.mu.Unlock()
		w.err = errEvidenceBackpressure
		w.mu.Unlock()
		w.store.gap(w.backend, "", "evidence_global_budget", "writes", 1)
		w.store.fail(errEvidenceBackpressure)
		return 0, errEvidenceBackpressure
	}
	w.store.stats.RawEvidencePendingBytes += uint64(len(data))
	if w.store.stats.RawEvidencePendingBytes > w.store.stats.RawEvidenceHighWaterBytes {
		w.store.stats.RawEvidenceHighWaterBytes = w.store.stats.RawEvidencePendingBytes
	}
	w.store.mu.Unlock()
	copy := append([]byte(nil), data...)
	w.pending += len(copy)
	w.queue <- copy
	w.mu.Unlock()
	return len(data), nil
}
func (w *evidenceWriter) release(n int) {
	w.mu.Lock()
	n = min(n, w.pending)
	w.pending -= n
	w.store.mu.Lock()
	w.store.stats.RawEvidencePendingBytes -= uint64(n)
	w.store.mu.Unlock()
	w.mu.Unlock()
}
func (w *evidenceWriter) run() {
	var runErr error
	defer func() {
		if err := w.sink.Close(); runErr == nil {
			runErr = err
		}
		w.mu.Lock()
		remaining := w.pending
		if w.err == nil {
			w.err = runErr
		}
		w.mu.Unlock()
		w.release(remaining)
		w.store.mu.Lock()
		w.store.stats.RawEvidenceWriters--
		if runErr != nil {
			w.store.stats.RawEvidenceDrainUnconfirmed = true
		}
		w.store.mu.Unlock()
		if runErr != nil {
			w.store.gap(w.backend, "", "evidence_write_unconfirmed", "bytes", uint64(remaining))
			w.store.fail(fmt.Errorf("%s raw evidence: %w", w.backend, runErr))
		}
		close(w.done)
	}()
	writer := bufio.NewWriterSize(w.sink, 64<<10)
	buffered := 0
	flush := func() error {
		if err := writer.Flush(); err != nil {
			return err
		}
		w.release(buffered)
		buffered = 0
		return nil
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case data, ok := <-w.queue:
			if !ok {
				runErr = flush()
				if runErr == nil {
					runErr = w.sink.Sync()
				}
				return
			}
			if _, runErr = writer.Write(data); runErr != nil {
				return
			}
			buffered += len(data)
			if buffered >= 256<<10 {
				if runErr = flush(); runErr != nil {
					return
				}
			}
		case <-ticker.C:
			if runErr = flush(); runErr != nil {
				return
			}
		}
	}
}
func (w *evidenceWriter) Close() error {
	w.closeOnce.Do(func() { w.mu.Lock(); w.closed = true; close(w.queue); w.mu.Unlock() })
	select {
	case <-w.done:
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.err
	case <-time.After(w.timeout):
		w.timeoutOnce.Do(func() {
			err := fmt.Errorf("%s raw evidence drain exceeded %s", w.backend, w.timeout)
			w.mu.Lock()
			if w.err == nil {
				w.err = err
			}
			w.mu.Unlock()
			w.store.mu.Lock()
			w.store.stats.RawEvidenceDrainUnconfirmed = true
			w.store.mu.Unlock()
			w.store.fail(err)
		})
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.err
	}
}
