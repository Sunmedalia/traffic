package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

var probeTransportBytes atomic.Int64
var errProbeTransportBackpressure = errors.New("TLS probe receive budget exhausted")

const probeTransportBudget = 32 << 20
const probeConnectionBudget = 8 << 20
const probeConnectionMessages = 16 << 10

type probeMessageReader interface {
	ReadMessage() (int, []byte, error)
	Close() error
}

// Read the probe socket independently of parsing and SQLite writes. Buffers are
// bounded by bytes as well as count; overload terminates this transport with a
// visible gap rather than silently parsing across missing events.
type probeTransport struct {
	reader           probeMessageReader
	queue            chan []byte
	done             chan struct{}
	stopOnce         sync.Once
	pending          atomic.Int64
	receivedMessages atomic.Uint64
	receivedBytes    atomic.Uint64
	dequeuedMessages atomic.Uint64
	dequeuedBytes    atomic.Uint64
	highWater        atomic.Int64
	overflows        atomic.Uint64
	err              error
}

func startProbeTransport(reader probeMessageReader, onError ...func(error)) *probeTransport {
	// Small events exhausted 1024 slots at only about 809 KiB in the lab.
	// Preserve the byte budget while allowing it to absorb a small-event burst.
	t := &probeTransport{reader: reader, queue: make(chan []byte, probeConnectionMessages), done: make(chan struct{})}
	go func() {
		defer close(t.done)
		defer close(t.queue)
		defer func() {
			if t.err != nil {
				for _, callback := range onError {
					callback(t.err)
				}
			}
		}()
		for {
			_, data, err := reader.ReadMessage()
			if err != nil {
				t.err = err
				return
			}
			t.receivedMessages.Add(1)
			t.receivedBytes.Add(uint64(len(data)))
			n := int64(len(data))
			if t.pending.Add(n) > probeConnectionBudget {
				t.err = t.overflow("connection_bytes")
				t.pending.Add(-n)
				return
			}
			if probeTransportBytes.Add(n) > probeTransportBudget {
				t.err = t.overflow("global_bytes")
				probeTransportBytes.Add(-n)
				t.pending.Add(-n)
				return
			}
			select {
			case t.queue <- data:
				for value := t.pending.Load(); value > t.highWater.Load(); {
					if old := t.highWater.Load(); value <= old || t.highWater.CompareAndSwap(old, value) {
						break
					}
				}
			default:
				t.err = t.overflow("message_count")
				t.release(data)
				return
			}
		}
	}()
	return t
}
func (t *probeTransport) overflow(reason string) error {
	t.overflows.Add(1)
	return fmt.Errorf("%w: reason=%s pending_bytes=%d queued_messages=%d global_bytes=%d", errProbeTransportBackpressure, reason, t.pending.Load(), len(t.queue), probeTransportBytes.Load())
}
func (t *probeTransport) release(data []byte) {
	n := int64(len(data))
	t.pending.Add(-n)
	probeTransportBytes.Add(-n)
}
func (t *probeTransport) next() ([]byte, error) {
	data, ok := <-t.queue
	if !ok {
		<-t.done
		return nil, t.err
	}
	t.release(data)
	t.dequeuedMessages.Add(1)
	t.dequeuedBytes.Add(uint64(len(data)))
	return data, nil
}
func (t *probeTransport) close() {
	t.stopOnce.Do(func() {
		_ = t.reader.Close()
		<-t.done
		for data := range t.queue {
			t.release(data)
		}
	})
}
