package main

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type fakeProbeReader struct {
	messages chan []byte
	stopped  chan struct{}
	once     sync.Once
}

func (r *fakeProbeReader) ReadMessage() (int, []byte, error) {
	select {
	case data, ok := <-r.messages:
		if !ok {
			return 0, nil, io.EOF
		}
		return 2, data, nil
	case <-r.stopped:
		return 0, nil, io.EOF
	}
}
func (r *fakeProbeReader) Close() error { r.once.Do(func() { close(r.stopped) }); return nil }
func newFakeProbeReader() *fakeProbeReader {
	return &fakeProbeReader{messages: make(chan []byte, probeConnectionMessages+1), stopped: make(chan struct{})}
}
func awaitProbeDone(t *testing.T, tr *probeTransport) {
	t.Helper()
	select {
	case <-tr.done:
	case <-time.After(time.Second):
		t.Fatal("probe receiver did not finish")
	}
}

func TestProbeTransportReceivesBurstWhileParserPaused(t *testing.T) {
	before := probeTransportBytes.Load()
	r := newFakeProbeReader()
	for i := 0; i < 512; i++ {
		r.messages <- []byte{byte(i >> 8), byte(i)}
	}
	close(r.messages)
	tr := startProbeTransport(r)
	defer tr.close()
	awaitProbeDone(t, tr)
	if tr.pending.Load() != 1024 {
		t.Fatal("receiver blocked on the parser", tr.pending.Load())
	}
	for i := 0; i < 512; i++ {
		data, err := tr.next()
		if err != nil || len(data) != 2 || int(data[0])*256+int(data[1]) != i {
			t.Fatal("probe messages reordered", i, data, err)
		}
	}
	if _, err := tr.next(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if probeTransportBytes.Load() != before {
		t.Fatal("probe byte reservation leaked")
	}
}
func TestProbeTransportBoundsAndEarlyParserExit(t *testing.T) {
	before := probeTransportBytes.Load()
	for _, size := range []int{1, 2 << 20} {
		r := newFakeProbeReader()
		for i := 0; i <= probeConnectionMessages; i++ {
			r.messages <- make([]byte, size)
			if size > 1 && i == 5 {
				break
			}
		}
		tr := startProbeTransport(r)
		awaitProbeDone(t, tr)
		if !errors.Is(tr.err, errProbeTransportBackpressure) {
			t.Fatal("overflow was silent", tr.err)
		}
		if tr.pending.Load() > probeConnectionBudget || probeTransportBytes.Load()-before > probeConnectionBudget {
			t.Fatal("receive memory budget exceeded")
		}
		tr.close()
		tr.close()
		if probeTransportBytes.Load() != before {
			t.Fatal("abandoned messages leaked budget")
		}
	}
	r := newFakeProbeReader()
	tr := startProbeTransport(r)
	tr.close()
	if probeTransportBytes.Load() != before {
		t.Fatal("idle receiver leaked budget")
	}
}
func TestProbeTransportGlobalBudget(t *testing.T) {
	before := probeTransportBytes.Load()
	probeTransportBytes.Add(probeTransportBudget)
	defer probeTransportBytes.Add(-probeTransportBudget)
	r := newFakeProbeReader()
	r.messages <- []byte("over global budget")
	tr := startProbeTransport(r)
	awaitProbeDone(t, tr)
	tr.close()
	if !errors.Is(tr.err, errProbeTransportBackpressure) || tr.pending.Load() != 0 || probeTransportBytes.Load() != before+probeTransportBudget {
		t.Fatal("global receive budget was not enforced", tr.err)
	}
}
