package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

var probeTransportBytes atomic.Int64
var probeFinalControlBytes atomic.Int64
var errProbeTransportBackpressure = errors.New("TLS probe receive budget exhausted")

const probeTransportBudget = 32 << 20
const probeConnectionBudget = 8 << 20
const probeConnectionMessages = 16 << 10
const probeFinalControlMaxBytes = 1024
const probeFinalControlBudget = 64 << 10

type probeMessageReader interface {
	ReadMessage() (int, []byte, error)
	Close() error
}

// probeMessage carries one received payload. shed is the number of messages
// discarded immediately before it while the queue was over budget, so the
// consumer can mark an explicit loss boundary before parsing data again.
type probeMessage struct {
	data         []byte
	shed         probeShed
	finalReserve bool
}

type probeShed struct {
	messages  uint64
	sequenced uint64
}

// Read the probe socket independently of parsing and evidence writes. Buffers
// are bounded by bytes as well as count. Overload no longer tears down the
// transport (which lost every event until reattach and reopened the attach
// window); instead the receiver sheds messages until the queue drains to half
// its budget, then hands the shed count to the consumer with the next message.
type probeTransport struct {
	reader           probeMessageReader
	queue            chan probeMessage
	done             chan struct{}
	stopOnce         sync.Once
	pending          atomic.Int64
	receivedMessages atomic.Uint64
	receivedBytes    atomic.Uint64
	dequeuedMessages atomic.Uint64
	dequeuedBytes    atomic.Uint64
	highWater        atomic.Int64
	overflows        atomic.Uint64
	shedMessages     atomic.Uint64
	shedBytes        atomic.Uint64
	lastOverflow     atomic.Pointer[string]
	tailShed         probeShed // shed after the last queued message; read after done
	err              error
}

func startProbeTransport(reader probeMessageReader, onError ...func(error)) *probeTransport {
	// Small events exhausted 1024 slots at only about 809 KiB in the lab.
	// Preserve the byte budget while allowing it to absorb a small-event burst.
	t := &probeTransport{reader: reader, queue: make(chan probeMessage, probeConnectionMessages+1), done: make(chan struct{})}
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
		shedding := false
		var shed probeShed
		finalReserved := false
		for {
			_, data, err := reader.ReadMessage()
			if err != nil {
				t.err, t.tailShed = err, shed
				return
			}
			t.receivedMessages.Add(1)
			t.receivedBytes.Add(uint64(len(data)))
			reason := "shedding"
			if !shedding || t.drained() {
				reason = t.reserve(data)
			}
			reserved := false
			if reason != "" {
				reserved = !finalReserved && t.reserveFinalControl(data)
				if !reserved {
					if reason != "shedding" {
						t.overflow(reason)
					}
					shedding = true
					shed.messages++
					if probeFrameHasSequence(data) {
						shed.sequenced++
					}
					t.shedMessages.Add(1)
					t.shedBytes.Add(uint64(len(data)))
					continue
				}
			}
			finalReserved = finalReserved || reserved
			shedding = false
			t.queue <- probeMessage{data: data, shed: shed, finalReserve: reserved}
			shed = probeShed{}
			for value := t.pending.Load(); value > t.highWater.Load(); {
				if old := t.highWater.Load(); value <= old || t.highWater.CompareAndSwap(old, value) {
					break
				}
			}
		}
	}()
	return t
}

// reserve accounts for one message, returning the overflow reason if it does
// not fit. A reserved message always has a free queue slot because only this
// goroutine sends and the slot check happens first.
func (t *probeTransport) reserve(data []byte) string {
	if len(t.queue) >= probeConnectionMessages {
		return "message_count"
	}
	n := int64(len(data))
	if t.pending.Add(n) > probeConnectionBudget {
		t.pending.Add(-n)
		return "connection_bytes"
	}
	if probeTransportBytes.Add(n) > probeTransportBudget {
		probeTransportBytes.Add(-n)
		t.pending.Add(-n)
		return "global_bytes"
	}
	return ""
}

// Keep the one terminal control in FIFO order even when data exhausted the
// normal receive budget. Only the first reserved control can use this slot.
func (t *probeTransport) reserveFinalControl(data []byte) bool {
	if len(data) > probeFinalControlMaxBytes || len(t.queue) == cap(t.queue) {
		return false
	}
	var frame protoFields
	if frame.parse(data) != nil || frame.ints[1] != 1 {
		return false
	}
	if _, ok := parseProbeDrainControl(string(frame.bytes[4])); !ok {
		return false
	}
	n := int64(len(data))
	if probeFinalControlBytes.Add(n) > probeFinalControlBudget {
		probeFinalControlBytes.Add(-n)
		return false
	}
	t.pending.Add(n)
	return true
}

func probeFrameHasSequence(data []byte) bool {
	var frame, event protoFields
	return frame.parse(data) == nil && frame.bytes[2] != nil &&
		event.parse(frame.bytes[2]) == nil && event.ints[17] != 0
}

// drained reports hysteresis: resume only once half the local budget and
// queue are free, so one slow parse does not alternate accept/shed per event.
func (t *probeTransport) drained() bool {
	return t.pending.Load() <= probeConnectionBudget/2 && len(t.queue) <= probeConnectionMessages/2 && probeTransportBytes.Load() <= probeTransportBudget/2
}

func (t *probeTransport) overflow(reason string) {
	t.overflows.Add(1)
	text := fmt.Errorf("%w: reason=%s pending_bytes=%d queued_messages=%d global_bytes=%d", errProbeTransportBackpressure, reason, t.pending.Load(), len(t.queue), probeTransportBytes.Load()).Error()
	t.lastOverflow.Store(&text)
}
func (t *probeTransport) release(message probeMessage) {
	n := int64(len(message.data))
	t.pending.Add(-n)
	if message.finalReserve {
		probeFinalControlBytes.Add(-n)
	} else {
		probeTransportBytes.Add(-n)
	}
}

// next returns the next payload and the number of messages shed before it.
// A final shed count with no following message is returned with the error.
func (t *probeTransport) next() ([]byte, probeShed, error) {
	message, ok := <-t.queue
	if !ok {
		<-t.done
		return nil, t.tailShed, t.err
	}
	t.release(message)
	t.dequeuedMessages.Add(1)
	t.dequeuedBytes.Add(uint64(len(message.data)))
	return message.data, message.shed, nil
}
func (t *probeTransport) close() {
	t.stopOnce.Do(func() {
		_ = t.reader.Close()
		<-t.done
		for message := range t.queue {
			t.release(message)
		}
	})
}
