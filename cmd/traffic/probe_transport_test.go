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
	idle     chan struct{}
	once     sync.Once
}

func (r *fakeProbeReader) ReadMessage() (int, []byte, error) {
	if len(r.messages) == 0 {
		select {
		case r.idle <- struct{}{}:
		default:
		}
	}
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
		data, shed, err := tr.next()
		if err != nil || shed.messages != 0 || len(data) != 2 || int(data[0])*256+int(data[1]) != i {
			t.Fatal("probe messages reordered", i, data, err)
		}
	}
	if _, _, err := tr.next(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if probeTransportBytes.Load() != before {
		t.Fatal("probe byte reservation leaked")
	}
}
func TestProbeTransportShedsAndRecoversWithinBounds(t *testing.T) {
	before := probeTransportBytes.Load()
	for _, size := range []int{1, 2 << 20} {
		r := newFakeProbeReader()
		total := probeConnectionMessages + 1
		if size > 1 {
			total = 6
		}
		for i := 0; i < total; i++ {
			r.messages <- make([]byte, size)
		}
		r.idle = make(chan struct{}, 1)
		tr := startProbeTransport(r)
		defer tr.close()
		// The next read starts after the receiver accounts for the entire burst.
		select {
		case <-r.idle:
		case <-time.After(time.Second):
			t.Fatal("probe receiver did not process the burst")
		}
		if tr.overflows.Load() != 1 || tr.shedMessages.Load() == 0 {
			t.Fatal("overflow was silent", tr.overflows.Load(), tr.shedMessages.Load())
		}
		if tr.pending.Load() > probeConnectionBudget || probeTransportBytes.Load()-before > probeConnectionBudget {
			t.Fatal("receive memory budget exceeded")
		}
		select {
		case <-tr.done:
			t.Fatal("overflow tore down the transport")
		default:
		}
		// Drain, then deliver one more message: it must carry the shed count.
		queued := len(tr.queue)
		for i := 0; i < queued; i++ {
			if _, shed, err := tr.next(); err != nil || shed.messages != 0 {
				t.Fatal("unexpected shed before boundary", shed, err)
			}
		}
		r.messages <- []byte("after")
		data, shed, err := tr.next()
		if err != nil || string(data) != "after" || shed.messages != tr.shedMessages.Load() {
			t.Fatal("shed boundary not delivered with next message", string(data), shed, err)
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
	r := newFakeProbeReader()
	r.messages <- []byte("over global budget")
	close(r.messages)
	tr := startProbeTransport(r)
	awaitProbeDone(t, tr)
	_, shed, err := tr.next()
	probeTransportBytes.Add(-probeTransportBudget)
	tr.close()
	if !errors.Is(err, io.EOF) || shed.messages != 1 || tr.overflows.Load() != 1 || tr.pending.Load() != 0 || probeTransportBytes.Load() != before {
		t.Fatal("global receive budget was not enforced", err, shed)
	}
}

func TestProbeTransportPreservesTerminalControlAndCountsOnlySequencedDrops(t *testing.T) {
	baseData, baseControls := probeTransportBytes.Load(), probeFinalControlBytes.Load()
	reader := newFakeProbeReader()
	// Enforce deterministic pressure without relying on disk or scheduler timing.
	probeTransportBytes.Add(probeTransportBudget)
	defer probeTransportBytes.Add(-probeTransportBudget)
	reader.messages <- encodeFakeProcessLog("unsequenced operational log")
	reader.messages <- encodeFakeTLSEvent(7, 1, "conn", "read", []byte("data"))
	drain := "traffic-control-v1:drained:seq=9,dropped=2,perf_lost=0"
	reader.messages <- encodeFakeProcessLog(drain)
	close(reader.messages)
	tr := startProbeTransport(reader)
	defer tr.close()
	awaitProbeDone(t, tr)
	data, shed, err := tr.next()
	var frame protoFields
	if err != nil || frame.parse(data) != nil || string(frame.bytes[4]) != drain {
		t.Fatalf("terminal control lost: %v, %q", err, frame.bytes[4])
	}
	if shed.messages != 2 || shed.sequenced != 1 {
		t.Fatalf("wrong loss accounting: %+v", shed)
	}
	if _, remainder, err := tr.next(); !errors.Is(err, io.EOF) || remainder != (probeShed{}) {
		t.Fatalf("unexpected terminal loss: %+v, %v", remainder, err)
	}
	if probeTransportBytes.Load() != baseData+probeTransportBudget || probeFinalControlBytes.Load() != baseControls {
		t.Fatal("receive queue leaked byte reservations")
	}
}

func TestProbeTransportFinalControlKeepsSheddingUntilDrained(t *testing.T) {
	r := newFakeProbeReader()
	first := make([]byte, 5<<20)
	drain := encodeFakeProcessLog("traffic-control-v1:drained:seq=9,dropped=0,perf_lost=0")
	r.messages <- first
	r.messages <- make([]byte, 4<<20)
	r.messages <- drain
	r.messages <- encodeFakeTLSEvent(9, 1, "conn", "read", []byte("still congested"))
	close(r.messages)

	tr := startProbeTransport(r)
	defer tr.close()
	awaitProbeDone(t, tr)
	if data, shed, err := tr.next(); len(data) != len(first) || shed != (probeShed{}) || err != nil {
		t.Fatalf("first message: bytes=%d, shed=%+v, err=%v", len(data), shed, err)
	}
	if data, shed, err := tr.next(); len(data) != len(drain) || shed != (probeShed{messages: 1}) || err != nil {
		t.Fatalf("final control: bytes=%d, shed=%+v, err=%v", len(data), shed, err)
	}
	if _, shed, err := tr.next(); shed != (probeShed{messages: 1, sequenced: 1}) || !errors.Is(err, io.EOF) {
		t.Fatalf("data resumed before the recovery threshold: shed=%+v, err=%v", shed, err)
	}
}
