package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

// controllableFileSink wraps an *os.File so tests can deterministically pause
// and resume disk writes or inject ENOSPC/EIO mid-stream while still writing
// real JSONL output to tls/stream.jsonl.
type controllableFileSink struct {
	mu       sync.Mutex
	file     *os.File
	gate     chan struct{} // nil or closed = unblocked; open = blocked
	entered  chan struct{} // signaled when a Write blocks on gate
	writeErr error
	syncErr  error
	closeErr error
}

func newControllableFileSink(t *testing.T, dir string) (*controllableFileSink, string) {
	t.Helper()
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tlsDir, "stream.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	closedGate := make(chan struct{})
	close(closedGate)
	return &controllableFileSink{
		file:    file,
		gate:    closedGate,
		entered: make(chan struct{}, 16),
	}, path
}

func (s *controllableFileSink) pause() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.gate:
		s.gate = make(chan struct{})
	default:
	}
}

func (s *controllableFileSink) resume() {
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	select {
	case <-gate:
	default:
		close(gate)
	}
}

func (s *controllableFileSink) failWrites(err error) {
	s.mu.Lock()
	s.writeErr = err
	s.mu.Unlock()
}

func (s *controllableFileSink) Write(data []byte) (int, error) {
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	select {
	case <-gate:
	default:
		select {
		case s.entered <- struct{}{}:
		default:
		}
		<-gate
	}
	s.mu.Lock()
	err := s.writeErr
	s.mu.Unlock()
	if err != nil {
		return 0, &os.PathError{Op: "write", Path: s.file.Name(), Err: err}
	}
	return s.file.Write(data)
}

func (s *controllableFileSink) Sync() error {
	s.mu.Lock()
	err := s.syncErr
	s.mu.Unlock()
	if err != nil {
		return &os.PathError{Op: "sync", Path: s.file.Name(), Err: err}
	}
	return s.file.Sync()
}

func (s *controllableFileSink) Close() error {
	s.mu.Lock()
	err := s.closeErr
	s.mu.Unlock()
	closeErr := s.file.Close()
	if err != nil {
		return &os.PathError{Op: "close", Path: s.file.Name(), Err: err}
	}
	return closeErr
}

func readStreamEvents(t *testing.T, path string) []session.RawEvent {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lines := session.NewJSONLines(file, evidenceMaxRecordBytes)
	var out []session.RawEvent
	for {
		var event session.RawEvent
		err := lines.Next(&event)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("unreadable JSONL record %d in %s: %v", len(out), path, err)
		}
		out = append(out, event)
	}
}

func sumGapJournalReason(t *testing.T, dir, reason string) uint64 {
	t.Helper()
	path := filepath.Join(dir, "gaps.jsonl")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	var sum uint64
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var gap session.GapEvent
		if err := json.Unmarshal(line, &gap); err != nil {
			t.Fatalf("invalid gaps.jsonl line %q: %v", string(line), err)
		}
		if gap.Reason == reason {
			sum += gap.Count
		}
	}
	return sum
}

func TestEvidenceBackpressurePolicyFlagAndHelp(t *testing.T) {
	for input, want := range map[string]evidenceBackpressurePolicy{
		"":       evidenceBackpressureStrict,
		"strict": evidenceBackpressureStrict,
		"stop":   evidenceBackpressureStrict,
		"drop":   evidenceBackpressureDrop,
		"shed":   evidenceBackpressureDrop,
	} {
		got, err := parseEvidenceBackpressurePolicy(input)
		if err != nil || got != want {
			t.Fatalf("parseEvidenceBackpressurePolicy(%q) = (%q, %v), want %q", input, got, err, want)
		}
	}
	for _, bad := range []string{"ignore", "unbounded", "unknown"} {
		if _, err := parseEvidenceBackpressurePolicy(bad); err == nil {
			t.Fatalf("accepted invalid policy %q", bad)
		}
	}
	if err := run([]string{"capture", "--evidence-backpressure", "invalid"}); err == nil || !strings.Contains(err.Error(), "evidence-backpressure") {
		t.Fatalf("CLI accepted invalid policy: %v", err)
	}
	if err := run([]string{"doctor", "--evidence-backpressure", "drop"}); err == nil || !strings.Contains(err.Error(), "not a doctor option") {
		t.Fatalf("doctor accepted capture backpressure flag: %v", err)
	}
	if err := run([]string{"capture", "--cn-help"}); err != nil {
		t.Fatalf("capture --cn-help failed: %v", err)
	}
}

func TestRecorderStrictPolicyStopsOnCongestionKeepingJSONLReadable(t *testing.T) {
	dir := t.TempDir()
	s := &Store{dir: dir}
	sink, streamPath := newControllableFileSink(t, dir)
	sink.pause()
	recorder := newRecorderWithPolicy(s, evidenceBackpressureStrict)
	recorder.customSink = sink
	recorder.writerCfg = &evidenceWriterConfig{
		policy:           evidenceBackpressureStrict,
		dataBudget:       4096,
		dataSlots:        8,
		globalDataBudget: 4096,
		timeout:          time.Second,
	}
	target := session.Target{PID: 100, ID: "100:strict", Service: "nginx", Ports: []int{443}}
	accepted := 0
	var overflowErr error
	for i := 0; i < 20; i++ {
		err := recorder.record("ecapture-1/100:strict", "ecapture", target, session.RawEvent{
			Type:       "data",
			Connection: "c1",
			Direction:  "read",
			Local:      "127.0.0.1:443",
			Client:     "192.0.2.1:5000",
			Data:       bytes.Repeat([]byte("x"), 600),
		})
		if err != nil {
			overflowErr = err
			break
		}
		accepted++
	}
	if !errors.Is(overflowErr, errEvidenceBackpressure) || accepted == 0 {
		t.Fatalf("expected strict backpressure after initial events: accepted=%d err=%v", accepted, overflowErr)
	}
	sink.resume()
	closeErr := recorder.close()
	if !errors.Is(closeErr, errEvidenceBackpressure) {
		t.Fatalf("expected backpressure error from close, got %v", closeErr)
	}
	events := readStreamEvents(t, streamPath)
	// 1 source record + all accepted data records must be complete valid JSONL.
	if len(events) != accepted+1 || events[0].Type != "source" {
		t.Fatalf("unexpected persisted records: got %d, want %d", len(events), accepted+1)
	}
	if finishCaptureState(s, false, false, false) == nil || s.stats.State != "failed" || s.stats.StopReason != "fatal_error" || s.stats.DrainState != "unverified" {
		t.Fatalf("strict overflow did not mark session failed: %+v", s.stats)
	}
}

func TestRecorderDropPolicyInsertsLossBeforeRecoveredDataAndPreventsCrossGapSplice(t *testing.T) {
	dir := t.TempDir()
	s := &Store{dir: dir}
	s.recordProbeExit("101:nginx", session.ProbeExit{DataDrained: true})
	sink, streamPath := newControllableFileSink(t, dir)
	sink.pause()
	recorder := newRecorderWithPolicy(s, evidenceBackpressureDrop)
	recorder.customSink = sink
	recorder.writerCfg = &evidenceWriterConfig{
		policy:               evidenceBackpressureDrop,
		dataBudget:           2048,
		controlBudget:        8192,
		dataSlots:            4,
		controlSlots:         32,
		globalDataBudget:     2048,
		globalControlReserve: 8192,
		timeout:              time.Second,
	}
	target := session.Target{PID: 101, ID: "101:nginx", Service: "nginx", Ports: []int{443}}
	source := "ecapture-1/101:nginx"

	// 1. Pre-congestion partial HTTP request on conn-1.
	if err := recorder.record(source, "ecapture", target, session.RawEvent{
		Type:       "data",
		Connection: "conn-1",
		Direction:  "read",
		Local:      "127.0.0.1:443",
		Client:     "192.0.2.10:40001",
		Data:       []byte("GET /partial-before "),
	}); err != nil {
		t.Fatal(err)
	}

	// 2. Saturate data queue while sink is blocked so subsequent complete events are shed.
	filler := bytes.Repeat([]byte("f"), 500)
	for i := 0; i < 12; i++ {
		if err := recorder.record(source, "ecapture", target, session.RawEvent{
			Type:       "data",
			Connection: "conn-1",
			Direction:  "read",
			Local:      "127.0.0.1:443",
			Client:     "192.0.2.10:40001",
			Data:       filler,
		}); err != nil {
			t.Fatalf("drop policy returned error during congestion: %v", err)
		}
	}
	// Also inject an oversized (>dataBudget) data event; it must be shed cleanly as 1 event.
	if err := recorder.record(source, "ecapture", target, session.RawEvent{
		Type:       "data",
		Connection: "conn-1",
		Direction:  "read",
		Local:      "127.0.0.1:443",
		Client:     "192.0.2.10:40001",
		Data:       bytes.Repeat([]byte("z"), 4096),
	}); err != nil {
		t.Fatalf("oversized event failed recorder in drop mode: %v", err)
	}

	if s.rawEvidenceQueueDropped.Load() == 0 {
		t.Fatal("expected shed events while sink was blocked")
	}
	shedDuringBlock := s.rawEvidenceQueueDropped.Load()

	// 3. Unblock sink and wait for buffered data to drain to 0.
	sink.resume()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pending := s.rawEvidencePendingBytes()
		if pending == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 4. Send post-recovery trailing fragment on conn-1 and a fresh request on conn-2.
	// Without an intervening loss record, "GET /partial-before " + "HTTP/1.1..."
	// would splice into a false request across the missing bytes!
	if err := recorder.record(source, "ecapture", target, session.RawEvent{
		Type:       "data",
		Connection: "conn-1",
		Direction:  "read",
		Local:      "127.0.0.1:443",
		Client:     "192.0.2.10:40001",
		Data:       []byte("HTTP/1.1\r\nHost: example\r\n\r\n"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.record(source, "ecapture", target, session.RawEvent{
		Type:       "data",
		Connection: "conn-2",
		Direction:  "read",
		Local:      "127.0.0.1:443",
		Client:     "192.0.2.10:40002",
		Data:       []byte("GET /clean-after HTTP/1.1\r\nHost: example\r\n\r\n"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.boundary("ecapture-1", session.RawEvent{Type: "end", Reason: "probe_stopped"}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.close(); err != nil {
		t.Fatal(err)
	}

	events := readStreamEvents(t, streamPath)
	if len(events) < 6 || events[0].Type != "source" || events[len(events)-1].Type != "end" {
		t.Fatalf("unexpected control framing: %+v", events)
	}
	lossIdx, postRecoveryIdx := -1, -1
	var recordedLoss uint64
	for i, ev := range events {
		if ev.Type == "loss" && ev.Reason == evidenceShedLossReason {
			lossIdx = i
			recordedLoss += ev.Count
			if ev.Unit != "events" {
				t.Fatalf("unexpected loss unit: %+v", ev)
			}
		}
		if ev.Type == "data" && bytes.HasPrefix(ev.Data, []byte("HTTP/1.1\r\nHost: example")) {
			postRecoveryIdx = i
		}
	}
	if lossIdx <= 1 || postRecoveryIdx <= lossIdx {
		t.Fatalf("loss marker did not precede recovered data: lossIdx=%d postRecoveryIdx=%d events=%+v", lossIdx, postRecoveryIdx, events)
	}
	if recordedLoss != shedDuringBlock || s.rawEvidenceQueueDropped.Load() != shedDuringBlock || s.stats.GapCounts["raw-tls/evidence_queue_shed/events"] != shedDuringBlock {
		t.Fatalf("loss count mismatch: stream=%d queue_dropped=%d gap_counts=%v", recordedLoss, s.rawEvidenceQueueDropped.Load(), s.stats.GapCounts)
	}
	if journalSum := sumGapJournalReason(t, dir, "evidence_queue_shed"); journalSum != shedDuringBlock {
		t.Fatalf("gaps.jsonl sum=%d != %d", journalSum, shedDuringBlock)
	}
	if err := finishCaptureStateReason(s, false, false, false, "duration"); err != nil {
		t.Fatalf("expected clean stop after bounded shedding, got %v", err)
	}
	if s.stats.State != "stopped" || s.stats.DrainState != "confirmed" || s.stats.RawEvidenceDrainUnconfirmed || s.rawEvidencePendingBytes() != 0 || s.stats.RawEvidenceWriters != 0 {
		t.Fatalf("unexpected session state after clean drain: %+v", s.stats)
	}
}

func TestRecorderMultiSourceConcurrencyAndExactLossAccounting(t *testing.T) {
	oldPorts := capturePorts
	capturePorts = map[int]bool{80: true, 443: true}
	defer func() { capturePorts = oldPorts }()

	dir := t.TempDir()
	s := &Store{dir: dir, iisAttached: true}
	sink, streamPath := newControllableFileSink(t, dir)
	recorder := newRecorderWithPolicy(s, evidenceBackpressureDrop)
	recorder.customSink = sink
	recorder.writerCfg = &evidenceWriterConfig{
		policy:               evidenceBackpressureDrop,
		dataBudget:           8192,
		controlBudget:        64 << 10,
		dataSlots:            16,
		controlSlots:         256,
		globalDataBudget:     8192,
		globalControlReserve: 64 << 10,
		timeout:              2 * time.Second,
	}

	// Verify IIS shed request does not falsely mark PlaintextObserved, while probe-gap still counts.
	sink.pause()
	iisTarget := session.Target{PID: 900, ID: "900:iis", Service: "iis", Ports: []int{443}}
	filler := bytes.Repeat([]byte("p"), 700)
	for i := 0; i < 20; i++ {
		if err := recorder.record("filler/0", "ecapture", session.Target{PID: 1, ID: "1:f", Service: "nginx"}, session.RawEvent{
			Type: "data", Connection: "f", Direction: "read", Data: filler,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.iis("windows-iis-1/900:iis", iisTarget, iisEvent{Type: "request", ID: "shed-req", Method: "GET", URL: "/shed"}); err != nil {
		t.Fatal(err)
	}
	if s.stats.PlaintextObserved {
		t.Fatal("shed IIS request falsely set PlaintextObserved=true")
	}
	nginxTarget := session.Target{PID: 902, ID: "902:nginx", Service: "nginx"}
	if err := recorder.openssl("windows-openssl/902:nginx", "openssl", nginxTarget, opensslEvent{
		Type: "data", Connection: "1", Direction: "read", Local: "127.0.0.1:443", Client: "192.0.2.1:9999", Data: filler,
	}); err != nil {
		t.Fatal(err)
	}
	if s.stats.PlaintextObserved {
		t.Fatal("shed nginx data falsely set PlaintextObserved=true")
	}
	if err := recorder.iis("windows-iis-1/900:iis", iisTarget, iisEvent{Type: "probe-gap", Reason: "unrecovered_receive", Kind: "receive", Count: 3}); err != nil {
		t.Fatal(err)
	}
	if s.stats.GapCounts["iis-httpapi/unrecovered_receive_receive/completions"] != 3 {
		t.Fatalf("IIS probe-gap lost during congestion: %+v", s.stats.GapCounts)
	}
	// Truncated OpenSSL event shed during congestion must not be double-counted as single_call_truncated.
	if err := recorder.openssl("preload/901:ossl", "openssl-preload", session.Target{PID: 901, ID: "901:ossl", Service: "openssl"}, opensslEvent{
		Type: "data", Connection: "901-1", Direction: "read", Local: "127.0.0.1:443", Client: "192.0.2.1:9999",
		Data: []byte("short"), OriginalLength: 100,
	}); err != nil {
		t.Fatal(err)
	}
	if s.stats.GapCounts["openssl-preload/single_call_truncated/bytes"] != 0 {
		t.Fatalf("shed OpenSSL event double-counted single_call_truncated: %+v", s.stats.GapCounts)
	}

	const numSources = 8
	const eventsPerSource = 60
	var wg sync.WaitGroup
	stopToggle := make(chan struct{})
	var toggleDone sync.WaitGroup
	toggleDone.Add(1)
	go func() {
		defer toggleDone.Done()
		paused := true
		for {
			select {
			case <-stopToggle:
				sink.resume()
				return
			case <-time.After(4 * time.Millisecond):
				if paused {
					sink.resume()
				} else {
					sink.pause()
				}
				paused = !paused
			}
		}
	}()

	for srcIdx := 0; srcIdx < numSources; srcIdx++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			source := fmt.Sprintf("ecapture-2/worker-%d", idx)
			target := session.Target{PID: 200 + idx, ID: fmt.Sprintf("%d:worker", 200+idx), Service: "nginx", Ports: []int{443}}
			for seq := 0; seq < eventsPerSource; seq++ {
				payload := append([]byte(fmt.Sprintf("seq=%d|", seq)), bytes.Repeat([]byte("m"), 350)...)
				if err := recorder.record(source, "ecapture", target, session.RawEvent{
					Type:       "data",
					Connection: fmt.Sprintf("c-%d", idx),
					Direction:  "read",
					Local:      "127.0.0.1:443",
					Client:     "192.0.2.55:12345",
					Data:       payload,
				}); err != nil {
					t.Errorf("source %s seq %d failed: %v", source, seq, err)
					return
				}
				if seq == eventsPerSource/2 && idx%2 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
			// Half the sources emit an explicit end; the other half rely on recorder.close()
			// flushing trailing pendingLoss.
			if idx%2 == 0 {
				if err := recorder.record(source, "ecapture", target, session.RawEvent{Type: "end", Reason: "probe_stopped"}); err != nil {
					t.Errorf("source %s end failed: %v", source, err)
				}
			}
		}(srcIdx)
	}

	wg.Wait()
	if err := recorder.boundary("ecapture-2", session.RawEvent{Type: "loss", Reason: "receive_queue_shed", Unit: "messages", Count: 5}); err != nil {
		t.Fatalf("boundary loss failed under congestion: %v", err)
	}
	close(stopToggle)
	toggleDone.Wait()
	sink.resume()

	if err := recorder.close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	events := readStreamEvents(t, streamPath)
	seenSource := map[string]bool{}
	endedSource := map[string]bool{}
	acceptedPerSource := map[string]int{}
	shedLossPerSource := map[string]uint64{}
	expectedSeq := map[string]int{}
	pendingGapForSeq := map[string]uint64{}
	var totalShedInStream uint64

	for idx, ev := range events {
		if ev.Type == "source" {
			if seenSource[ev.Source] {
				t.Fatalf("duplicate source at %d: %s", idx, ev.Source)
			}
			seenSource[ev.Source] = true
			continue
		}
		if !seenSource[ev.Source] {
			t.Fatalf("event at %d before source registration: %+v", idx, ev)
		}
		if endedSource[ev.Source] {
			t.Fatalf("event at %d after end marker: %+v", idx, ev)
		}
		switch ev.Type {
		case "end":
			endedSource[ev.Source] = true
		case "loss":
			if ev.Reason == evidenceShedLossReason {
				shedLossPerSource[ev.Source] += ev.Count
				pendingGapForSeq[ev.Source] += ev.Count
				totalShedInStream += ev.Count
			}
		default:
			acceptedPerSource[ev.Source]++
			if strings.HasPrefix(ev.Source, "ecapture-2/worker-") {
				prefix, _, ok := strings.Cut(string(ev.Data), "|")
				if !ok || !strings.HasPrefix(prefix, "seq=") {
					t.Fatalf("corrupted payload on %s: %q", ev.Source, string(ev.Data))
				}
				seq, err := strconv.Atoi(strings.TrimPrefix(prefix, "seq="))
				if err != nil {
					t.Fatal(err)
				}
				want := expectedSeq[ev.Source] + int(pendingGapForSeq[ev.Source])
				if seq != want {
					t.Fatalf("source %s seq=%d without matching preceding loss (expected %d, lastExpected=%d, pendingGap=%d)",
						ev.Source, seq, want, expectedSeq[ev.Source], pendingGapForSeq[ev.Source])
				}
				expectedSeq[ev.Source] = seq + 1
				pendingGapForSeq[ev.Source] = 0
			}
		}
	}

	for idx := 0; idx < numSources; idx++ {
		source := fmt.Sprintf("ecapture-2/worker-%d", idx)
		totalAccounted := acceptedPerSource[source] + int(shedLossPerSource[source])
		if totalAccounted != eventsPerSource {
			t.Fatalf("source %s accounted=%d (accepted=%d + shed=%d) != %d",
				source, totalAccounted, acceptedPerSource[source], shedLossPerSource[source], eventsPerSource)
		}
		// Any trailing dropped events after the last accepted data event must appear in pendingGapForSeq.
		if expectedSeq[source]+int(pendingGapForSeq[source]) != eventsPerSource {
			t.Fatalf("source %s missing trailing loss before end/close: expectedSeq=%d trailingLoss=%d",
				source, expectedSeq[source], pendingGapForSeq[source])
		}
		if idx%2 == 0 && !endedSource[source] {
			t.Fatalf("source %s missing end record", source)
		}
	}

	if totalShedInStream != s.rawEvidenceQueueDropped.Load() || s.stats.GapCounts["raw-tls/evidence_queue_shed/events"] != s.rawEvidenceQueueDropped.Load() {
		t.Fatalf("global shed mismatch: stream=%d queue_dropped=%d gap_counts=%+v",
			totalShedInStream, s.rawEvidenceQueueDropped.Load(), s.stats.GapCounts)
	}
	if journalSum := sumGapJournalReason(t, dir, "evidence_queue_shed"); journalSum != s.rawEvidenceQueueDropped.Load() {
		t.Fatalf("gaps.jsonl sum=%d != queue_dropped=%d", journalSum, s.rawEvidenceQueueDropped.Load())
	}
}

func TestRecorderObservesOnlySelectedNonemptyNginxPlaintext(t *testing.T) {
	oldPorts := capturePorts
	capturePorts = map[int]bool{443: true}
	defer func() { capturePorts = oldPorts }()
	s := &Store{dir: t.TempDir()}
	recorder := newRecorder(s)
	t.Cleanup(func() {
		if err := recorder.close(); err != nil {
			t.Error(err)
		}
	})
	target := session.Target{PID: 900, ID: "900:nginx", Service: "nginx"}
	for _, test := range []struct {
		event opensslEvent
		want  bool
	}{
		{event: opensslEvent{Type: "close", Connection: "1"}},
		{event: opensslEvent{Type: "data", Direction: "read", Local: "127.0.0.1:8443", Client: "127.0.0.1:60000", Data: []byte("filtered")}},
		{event: opensslEvent{Type: "data", Direction: "read", Local: "127.0.0.1:443", Client: "127.0.0.1:60000"}},
		{event: opensslEvent{Type: "data", Direction: "read", Local: "127.0.0.1:443", Client: "127.0.0.1:60000", Data: []byte("observed")}, want: true},
	} {
		if err := recorder.openssl("windows-openssl/900:nginx", "openssl", target, test.event); err != nil {
			t.Fatal(err)
		}
		if s.stats.PlaintextObserved != test.want {
			t.Fatalf("plaintext_observed=%v for event %+v", s.stats.PlaintextObserved, test.event)
		}
		if s.plaintextObserved.Load() != test.want || s.iisPlaintext.Load() {
			t.Fatalf("incorrect plaintext fast path state for event %+v", test.event)
		}
	}
}

func TestRecorderSustainedCongestionStopDeadlineAndHardWriteFailure(t *testing.T) {
	t.Run("stop_deadline_exceeded_under_sustained_congestion", func(t *testing.T) {
		dir := t.TempDir()
		s := &Store{dir: dir}
		sink, _ := newControllableFileSink(t, dir)
		sink.pause()
		recorder := newRecorderWithPolicy(s, evidenceBackpressureDrop)
		recorder.customSink = sink
		recorder.writerCfg = &evidenceWriterConfig{
			policy:               evidenceBackpressureDrop,
			dataBudget:           2048,
			controlBudget:        8192,
			dataSlots:            4,
			controlSlots:         16,
			globalDataBudget:     2048,
			globalControlReserve: 8192,
			timeout:              30 * time.Millisecond,
		}
		target := session.Target{PID: 300, ID: "300:hung", Service: "nginx"}
		// Send >64 KiB total or trigger flush so sink.Write blocks on gate.
		payload := bytes.Repeat([]byte("b"), 900)
		for i := 0; i < 20; i++ {
			if err := recorder.record("ecapture-3/300:hung", "ecapture", target, session.RawEvent{
				Type: "data", Connection: "c", Direction: "read", Data: payload,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if s.rawEvidenceQueueDropped.Load() == 0 {
			t.Fatal("expected shedding under sustained congestion")
		}
		// Wait for ticker flush to enter blocked sink.Write.
		select {
		case <-sink.entered:
		case <-time.After(time.Second):
			t.Fatal("writer did not enter blocked sink")
		}

		started := time.Now()
		budgetExceeded, closeErr := shutdownWithin(func() {}, recorder.close, 200*time.Millisecond)
		if budgetExceeded || closeErr == nil || !errors.Is(closeErr, errEvidenceDrainTimeout) || time.Since(started) > time.Second {
			t.Fatalf("unexpected shutdown result: budgetExceeded=%v err=%v elapsed=%s", budgetExceeded, closeErr, time.Since(started))
		}
		s.fail(closeErr)
		fatal := finishCaptureStateReason(s, false, false, budgetExceeded, "signal")
		if fatal == nil || s.stats.State != "failed" || s.stats.DrainState != "unverified" || !s.stats.RawEvidenceDrainUnconfirmed {
			t.Fatalf("unconfirmed drain was not surfaced in session status: fatal=%v stats=%+v", fatal, s.stats)
		}
		if s.stats.GapCounts["raw-tls/evidence_queue_shed/events"] != s.rawEvidenceQueueDropped.Load() {
			t.Fatalf("shed gap count not flushed on drain timeout: queue_dropped=%d gaps=%+v", s.rawEvidenceQueueDropped.Load(), s.stats.GapCounts)
		}

		// Cleanup blocked goroutine.
		sink.resume()
		<-recorder.writer.done
	})

	t.Run("hard_enospc_and_eio_override_drop_mode_congestion", func(t *testing.T) {
		for _, tc := range []struct {
			errno     syscall.Errno
			gapReason string
			checkFn   func(error) bool
		}{
			{errno: syscall.ENOSPC, gapReason: "evidence_write_enospc", checkFn: isEvidenceNoSpace},
			{errno: syscall.EIO, gapReason: "evidence_write_eio", checkFn: isEvidenceIOError},
		} {
			dir := t.TempDir()
			s := &Store{dir: dir}
			sink, _ := newControllableFileSink(t, dir)
			sink.pause()
			recorder := newRecorderWithPolicy(s, evidenceBackpressureDrop)
			recorder.customSink = sink
			recorder.writerCfg = &evidenceWriterConfig{
				policy:               evidenceBackpressureDrop,
				dataBudget:           4096,
				controlBudget:        8192,
				dataSlots:            4,
				controlSlots:         16,
				globalDataBudget:     4096,
				globalControlReserve: 8192,
				timeout:              time.Second,
			}
			target := session.Target{PID: 400, ID: "400:hard", Service: "nginx"}
			chunk := bytes.Repeat([]byte("h"), 1000)
			for i := 0; i < 10; i++ {
				if err := recorder.record("ecapture-4/400:hard", "ecapture", target, session.RawEvent{
					Type: "data", Connection: "c", Direction: "read", Data: chunk,
				}); err != nil {
					t.Fatal(err)
				}
			}
			// Inject hard error and unblock sink so flush encounters ENOSPC/EIO.
			sink.failWrites(tc.errno)
			sink.resume()

			var observedErr error
			deadline := time.Now().Add(2 * time.Second)
			var attempts atomic.Int32
			for time.Now().Before(deadline) {
				attempts.Add(1)
				err := recorder.record("ecapture-4/400:hard", "ecapture", target, session.RawEvent{
					Type: "data", Connection: "c", Direction: "read", Data: chunk,
				})
				if err != nil {
					observedErr = err
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !tc.checkFn(observedErr) || !errors.Is(observedErr, tc.errno) || isEvidenceCongestion(observedErr) {
				t.Fatalf("drop mode masked hard error %v: got %v", tc.errno, observedErr)
			}
			closeErr := recorder.close()
			if !tc.checkFn(closeErr) || !errors.Is(closeErr, tc.errno) {
				t.Fatalf("close lost hard error %v: got %v", tc.errno, closeErr)
			}
			if s.stats.GapCounts["raw-tls/"+tc.gapReason+"/errors"] != 1 || !s.stats.RawEvidenceDrainUnconfirmed {
				t.Fatalf("missing hard error gap or drain flag: %+v", s.stats)
			}
			if finishCaptureState(s, false, false, false) == nil || s.stats.State != "failed" || s.stats.DrainState != "unverified" {
				t.Fatalf("session state did not fail on %v: %+v", tc.errno, s.stats)
			}
		}
	})

	t.Run("global_budget_across_multiple_writers_and_open_failure", func(t *testing.T) {
		// Strict global budget across two writers sharing one Store.
		sStrict := &Store{dir: t.TempDir()}
		g1, g2 := make(chan struct{}), make(chan struct{})
		w1 := newEvidenceWriterWithConfig(sStrict, &blockingEvidenceSink{gate: g1}, "w1", evidenceWriterConfig{
			policy: evidenceBackpressureStrict, dataBudget: 4096, dataSlots: 8, globalDataBudget: 3000, timeout: time.Second,
		})
		w2 := newEvidenceWriterWithConfig(sStrict, &blockingEvidenceSink{gate: g2}, "w2", evidenceWriterConfig{
			policy: evidenceBackpressureStrict, dataBudget: 4096, dataSlots: 8, globalDataBudget: 3000, timeout: time.Second,
		})
		if _, err := w1.Write(make([]byte, 2000)); err != nil {
			t.Fatal(err)
		}
		if _, err := w2.Write(make([]byte, 1500)); !errors.Is(err, errEvidenceBackpressure) {
			t.Fatalf("expected global budget backpressure, got %v", err)
		}
		if sStrict.stats.GapCounts["w2/evidence_global_budget/writes"] != 1 {
			t.Fatalf("missing global budget gap: %+v", sStrict.stats.GapCounts)
		}
		close(g1)
		close(g2)
		_ = w1.Close()
		_ = w2.Close()

		// Stream creation failure fails Store and returns classified hard error on close.
		badDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(badDir, "tls"), []byte("not-a-dir"), 0600); err != nil {
			t.Fatal(err)
		}
		sOpen := &Store{dir: badDir}
		recOpen := newRecorderWithPolicy(sOpen, evidenceBackpressureDrop)
		err := recOpen.record("s1", "ecapture", session.Target{PID: 1, ID: "1:x"}, session.RawEvent{Type: "data", Direction: "read"})
		if err == nil || isEvidenceCongestion(err) {
			t.Fatalf("expected hard open failure, got %v", err)
		}
		if closeErr := recOpen.close(); !errors.Is(closeErr, errEvidenceWriteFailure) {
			t.Fatalf("expected classified failure on close, got %v", closeErr)
		}
		if sOpen.fatal == nil || sOpen.stats.GapCounts["raw-tls/evidence_write_error/errors"] != 1 {
			t.Fatalf("open failure not recorded as fatal: fatal=%v gaps=%+v", sOpen.fatal, sOpen.stats.GapCounts)
		}
	})
}

func TestDropWritersShareIndependentGlobalControlAndDataBudgets(t *testing.T) {
	s := &Store{}
	cfg := evidenceWriterConfig{
		policy: evidenceBackpressureDrop, dataBudget: 128, controlBudget: 128,
		globalDataBudget: 128, globalControlReserve: 64, timeout: time.Second,
	}
	gate := make(chan struct{})
	control := newEvidenceWriterWithConfig(s, &blockingEvidenceSink{gate: gate}, "control", cfg)
	data := newEvidenceWriterWithConfig(s, &blockingEvidenceSink{gate: gate}, "data", cfg)
	defer func() {
		close(gate)
		_ = control.Close()
		_ = data.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		if evidencePending(s.rawEvidencePending.Load()).control() != 0 || s.rawEvidencePendingBytes() != 0 {
			t.Fatalf("pending evidence leaked: control=%d total=%d", evidencePending(s.rawEvidencePending.Load()).control(), s.rawEvidencePendingBytes())
		}
	}()
	if err := control.writeControl(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if accepted, err := data.writeData(make([]byte, 128)); !accepted || err != nil {
		t.Fatalf("another writer's control reservation consumed data budget: accepted=%t err=%v", accepted, err)
	}
	if err := data.writeControl([]byte{1}); !errors.Is(err, errEvidenceControlOverflow) {
		t.Fatalf("expected exhausted global control budget, got %v", err)
	}
}

func TestDropRecorderSkipsEncodingWhenBudgetCannotFitPayload(t *testing.T) {
	s := &Store{dir: t.TempDir()}
	w := newRecorderWithPolicy(s, evidenceBackpressureDrop)
	w.writerCfg = &evidenceWriterConfig{dataBudget: 256}
	t.Cleanup(func() { _ = w.close() })
	// An out-of-range timestamp would fail json.Marshal if the event reached it.
	accepted, err := w.recordOutcome("source", "ecapture", session.Target{}, session.RawEvent{
		Type: "data", Data: make([]byte, 256), Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil || accepted {
		t.Fatalf("oversized event accepted=%v, err=%v", accepted, err)
	}
	if err := w.close(); err != nil {
		t.Fatal(err)
	}
	events := readRawEventsFromStream(t, filepath.Join(s.dir, "tls", "stream.jsonl"))
	if len(events) != 2 || events[0].Type != "source" || events[1].Type != "loss" ||
		events[1].Count != 1 || events[1].Reason != evidenceShedLossReason {
		t.Fatalf("missing source or shed marker: %+v", events)
	}
}

func TestEvidenceSyncFailureReportsFlushedBytesAsUnconfirmed(t *testing.T) {
	dir := t.TempDir()
	s := &Store{dir: dir}
	sink, _ := newControllableFileSink(t, dir)
	sink.syncErr = syscall.EIO
	w := newEvidenceWriter(s, sink, "raw-tls")
	data := []byte("{\"type\":\"data\"}\n")
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, errEvidenceIO) {
		t.Fatalf("expected classified sync error, got %v", err)
	}
	if got := s.stats.GapCounts["raw-tls/evidence_write_unconfirmed/bytes"]; got != uint64(len(data)) {
		t.Fatalf("unconfirmed bytes = %d, want %d", got, len(data))
	}
}
