package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/encoding/protowire"
)

func encodeFakeProcessLog(msg string) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, 1) // LOG_TYPE_PROCESS_LOG
	b = protowire.AppendTag(b, 4, protowire.BytesType)
	b = protowire.AppendString(b, msg)
	return b
}

func encodeFakeTLSEvent(seq uint64, pid int, streamID, direction string, payload []byte) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 3, protowire.BytesType)
	inner = protowire.AppendString(inner, "127.0.0.1")
	inner = protowire.AppendTag(inner, 4, protowire.VarintType)
	inner = protowire.AppendVarint(inner, 54321)
	inner = protowire.AppendTag(inner, 5, protowire.BytesType)
	inner = protowire.AppendString(inner, "127.0.0.1")
	inner = protowire.AppendTag(inner, 6, protowire.VarintType)
	inner = protowire.AppendVarint(inner, 443)
	inner = protowire.AppendTag(inner, 7, protowire.VarintType)
	inner = protowire.AppendVarint(inner, uint64(pid))
	inner = protowire.AppendTag(inner, 11, protowire.BytesType)
	inner = protowire.AppendBytes(inner, payload)
	inner = protowire.AppendTag(inner, 14, protowire.BytesType)
	inner = protowire.AppendString(inner, direction)
	inner = protowire.AppendTag(inner, 16, protowire.BytesType)
	inner = protowire.AppendString(inner, streamID)
	if seq > 0 {
		inner = protowire.AppendTag(inner, 17, protowire.VarintType)
		inner = protowire.AppendVarint(inner, seq)
	}

	var outer []byte
	outer = protowire.AppendTag(outer, 1, protowire.VarintType)
	outer = protowire.AppendVarint(outer, 2) // LOG_TYPE_EVENT
	outer = protowire.AppendTag(outer, 2, protowire.BytesType)
	outer = protowire.AppendBytes(outer, inner)
	return outer
}

type scriptedProbe struct {
	messages      chan []byte
	closed        chan struct{}
	interrupted   chan struct{}
	closeOnce     sync.Once
	interruptOnce sync.Once
	reapOnce      sync.Once
	readErr       error
	cleanExit     bool
	waitErr       error
	reaped        atomic.Bool
	onInterrupt   func(*scriptedProbe)
}

func newScriptedProbe(onInterrupt func(*scriptedProbe)) *scriptedProbe {
	return &scriptedProbe{
		messages:    make(chan []byte, 256),
		closed:      make(chan struct{}),
		interrupted: make(chan struct{}),
		readErr:     io.EOF,
		cleanExit:   true,
		onInterrupt: onInterrupt,
	}
}

func (p *scriptedProbe) ReadMessage() (int, []byte, error) {
	select {
	case msg, ok := <-p.messages:
		if !ok {
			return 0, nil, p.readErr
		}
		return websocket.BinaryMessage, msg, nil
	case <-p.closed:
		return 0, nil, errors.New("probe reader closed")
	}
}

func (p *scriptedProbe) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *scriptedProbe) interrupt() {
	p.interruptOnce.Do(func() {
		close(p.interrupted)
		if p.onInterrupt != nil {
			go p.onInterrupt(p)
		}
	})
}

func (p *scriptedProbe) reap(_ time.Duration) (bool, error) {
	p.reapOnce.Do(func() {
		p.interrupt()
		p.reaped.Store(true)
	})
	return p.cleanExit, p.waitErr
}

func runScriptedTLSProbe(
	t *testing.T,
	ctx context.Context,
	s *Store,
	recorder *eventRecorder,
	probe *scriptedProbe,
	logSink *probeLog,
	localDrain, localStop time.Duration,
	targetPID int,
	targetID string,
	ready func(),
) error {
	t.Helper()
	probeKey := fmt.Sprintf("ecapture//lib/libssl.so.3/0/%d", targetPID)
	var stopAt atomic.Int64
	var drainTimedOut atomic.Bool
	reapBudget := func() time.Duration {
		if ns := stopAt.Load(); ns > 0 {
			remaining := localStop - time.Since(time.Unix(0, ns))
			if remaining <= 0 {
				return 0
			}
			if drainTimedOut.Load() {
				return min(50*time.Millisecond, max(10*time.Millisecond, remaining/4))
			}
			return min(5*time.Second, max(25*time.Millisecond, remaining/2))
		}
		return min(2*time.Second, localDrain)
	}
	exitRecorded := false
	recordExit := func(exit session.ProbeExit) {
		exitRecorded = true
		s.recordProbeExit(probeKey, exit)
	}
	defer func() {
		cleanExit, _ := probe.reap(reapBudget())
		if !exitRecorded {
			recordExit(session.ProbeExit{
				DataDrained:       false,
				TransportDetached: cleanExit,
				RuntimeState:      "probe exited before drain confirmation",
			})
		}
	}()
	return consumeTLSProbe(
		ctx, s, recorder, "/lib/libssl.so.3", probeKey, probe, probe, logSink, false,
		localDrain, &stopAt, &drainTimedOut, reapBudget, recordExit,
		func(pid int, _ string) string {
			if pid == targetPID {
				return targetID
			}
			return ""
		},
		ready,
	)
}

func TestParseProbeDrainControl(t *testing.T) {
	summary, ok := parseProbeDrainControl("traffic-control-v1:drained:seq=42,dropped=3,perf_lost=1,future=9")
	if !ok || summary.sequence != 42 || summary.dropped != 3 || summary.perfLost != 1 {
		t.Fatalf("unexpected parse result: ok=%v summary=%+v", ok, summary)
	}
	for _, invalid := range []string{
		"",
		"traffic-control-v1:ready",
		"traffic-control-v1:drained:",
		"traffic-control-v1:drained:dropped=0",
		"traffic-control-v1:drained:seq=abc",
		"traffic-control-v1:drained:seq=1,bad",
	} {
		if _, ok := parseProbeDrainControl(invalid); ok {
			t.Fatalf("accepted invalid drain control %q", invalid)
		}
	}
}

func TestConsumeTLSProbePrefersStreamIDAndKeepsEndpointFallback(t *testing.T) {
	const pid, identity = 7890, "7890:100"
	oldPorts := capturePorts
	capturePorts = map[int]bool{443: true}
	defer func() { capturePorts = oldPorts }()
	target := session.Target{ID: identity, PID: pid, Service: "nginx"}
	s := &Store{dir: t.TempDir(), stats: Stats{Targets: []session.Target{target}}}
	recorder := newRecorder(s)
	t.Cleanup(func() { _ = recorder.close() })
	probe := newScriptedProbe(nil)
	stream := identity + "/connection"
	probe.messages <- encodeFakeTLSEvent(1, pid, stream, "read", []byte("first"))
	probe.messages <- encodeFakeTLSEvent(2, pid, stream, "write", []byte("second"))
	probe.messages <- encodeFakeTLSEvent(3, pid, "", "read", []byte("fallback"))
	close(probe.messages)
	if err := runScriptedTLSProbe(t, context.Background(), s, recorder, probe, nil, time.Second, time.Second, pid, identity, func() {}); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if err := recorder.close(); err != nil {
		t.Fatal(err)
	}
	events := readRawEventsFromStream(t, filepath.Join(s.dir, "tls", "stream.jsonl"))
	if len(events) != 5 || events[0].Type != "source" || events[0].Target == nil ||
		events[0].Target.ID != identity || events[0].Target.Service != target.Service ||
		events[4].Type != "end" {
		t.Fatalf("source and boundary records: %+v", events)
	}
	if !strings.HasSuffix(events[1].Connection, "/"+stream) || events[2].Connection != events[1].Connection ||
		events[1].Direction != "read" || events[2].Direction != "write" ||
		!strings.HasSuffix(events[3].Connection, "/7890/127.0.0.1:54321|127.0.0.1:443") {
		t.Fatalf("connection and direction records: %+v", events[1:4])
	}
	for _, event := range events[1:] {
		if event.Source != events[0].Source {
			t.Fatalf("source changed: %+v", event)
		}
	}
}

func TestProbeLogPreservesBytesAndCountsColoredLoss(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "probe.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	s := &Store{}
	log := &probeLog{store: s, file: file}
	var want []byte
	for _, line := range []string{"ordinary log\n", "\x1b[31mlost_samples=2\x1b[0m\n", "lost_\x1b[31msamples=3\x1b[0m\n"} {
		want = append(want, line...)
		if n, err := log.Write([]byte(line)); n != len(line) || err != nil {
			t.Fatalf("write %q: bytes=%d err=%v", line, n, err)
		}
	}
	log.reconcilePerfLost(5)
	got, err := os.ReadFile(file.Name())
	if err != nil || !bytes.Equal(got, want) || s.stats.TLSDropped != 5 {
		t.Fatalf("log bytes=%q, dropped=%d, err=%v", got, s.stats.TLSDropped, err)
	}
}

func TestCaptureTLSNormalStopDrainsTailAndConfirmsFinalBoundary(t *testing.T) {
	oldPorts := capturePorts
	capturePorts = map[int]bool{443: true}
	defer func() { capturePorts = oldPorts }()

	dir := t.TempDir()
	s, err := openStore(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	s.stats.TLSCoverage = "unverified"
	recorder := newRecorder(s)
	logFile, err := os.OpenFile(filepath.Join(dir, "probe.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	logSink := &probeLog{file: logFile, store: s}

	targetPID := 4242
	targetID := "4242:100"
	s.stats.Targets = []session.Target{{PID: targetPID, ID: targetID, Service: "nginx", Library: "/lib/libssl.so.3"}}

	probe := newScriptedProbe(func(p *scriptedProbe) {
		_, _ = logSink.Write([]byte("WRN Perf buffer full, samples lost lost_samples=2\n"))
		for seq := uint64(6); seq <= 12; seq++ {
			req := fmt.Sprintf("GET /tail/%d HTTP/1.1\r\nHost: localhost\r\nX-Traffic-Request-ID: req-%d\r\n\r\n", seq, seq)
			p.messages <- encodeFakeTLSEvent(seq, targetPID, "4242_inode_1", "read", []byte(req))
		}
		p.messages <- encodeFakeProcessLog("traffic-control-v1:drained:seq=12,dropped=0,perf_lost=2")
		close(p.messages)
	})
	probe.messages <- encodeFakeProcessLog("traffic-control-v1:ready")
	for seq := uint64(1); seq <= 5; seq++ {
		req := fmt.Sprintf("GET /active/%d HTTP/1.1\r\nHost: localhost\r\nX-Traffic-Request-ID: req-%d\r\n\r\n", seq, seq)
		probe.messages <- encodeFakeTLSEvent(seq, targetPID, "4242_inode_1", "read", []byte(req))
	}

	ctx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- runScriptedTLSProbe(t, ctx, s, recorder, probe, logSink, 2*time.Second, 4*time.Second, targetPID, targetID, func() {
			select {
			case readyCh <- struct{}{}:
			default:
			}
		})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		default:
		}
	}()

	select {
	case <-readyCh:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not report ready")
	}
	// Wait until active events 1..5 are persisted before stopping.
	streamPath := filepath.Join(dir, "tls", "stream.jsonl")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(streamPath)
		if bytes.Contains(data, []byte("req-5")) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	var runErr error
	budgetExceeded, closeErr := shutdownWithin(func() { runErr = <-done }, recorder.close, 4*time.Second)
	if budgetExceeded || closeErr != nil || runErr != nil {
		t.Fatalf("budgetExceeded=%v closeErr=%v runErr=%v", budgetExceeded, closeErr, runErr)
	}
	if err := finishCaptureStateReason(s, false, false, budgetExceeded, "signal"); err != nil {
		t.Fatalf("finishCaptureStateReason: %v", err)
	}
	if !probe.reaped.Load() {
		t.Fatal("probe process was not reaped")
	}
	if s.stats.State != "stopped" || s.stats.DrainState != "confirmed" || s.stats.TLSCoverage != "unverified" {
		t.Fatalf("unexpected final status: state=%s drain=%s coverage=%s exits=%+v gaps=%+v",
			s.stats.State, s.stats.DrainState, s.stats.TLSCoverage, s.stats.ProbeExits, s.stats.GapCounts)
	}
	if s.stats.TLSDropped != 2 {
		t.Fatalf("TLSDropped = %d, want 2 (no double counting between stderr and drain summary)", s.stats.TLSDropped)
	}

	events := readRawEventsFromStream(t, streamPath)
	var dataEvents []session.RawEvent
	sawEnd := false
	for _, ev := range events {
		if ev.Type == "data" {
			dataEvents = append(dataEvents, ev)
		}
		if ev.Type == "end" && ev.Reason == "probe_stopped" {
			sawEnd = true
		}
	}
	if len(dataEvents) != 12 || !sawEnd {
		t.Fatalf("persisted %d data events (want 12), sawEnd=%v", len(dataEvents), sawEnd)
	}
	for i := 1; i <= 12; i++ {
		marker := fmt.Sprintf("X-Traffic-Request-ID: req-%d\r\n", i)
		if !bytes.Contains(dataEvents[i-1].Data, []byte(marker)) {
			t.Fatalf("event %d missing %q", i, marker)
		}
	}
}

func TestCaptureTLSUnconfirmedHungMismatchInterruptedAndAbnormalExit(t *testing.T) {
	oldPorts := capturePorts
	capturePorts = map[int]bool{443: true}
	defer func() { capturePorts = oldPorts }()

	targetPID := 5151
	targetID := "5151:200"

	t.Run("legacy-no-confirm", func(t *testing.T) {
		dir := t.TempDir()
		s, _ := openStore(dir, true)
		recorder := newRecorder(s)
		probe := newScriptedProbe(func(p *scriptedProbe) {
			p.messages <- encodeFakeTLSEvent(2, targetPID, "5151_inode_1", "read", []byte("GET /tail HTTP/1.1\r\n\r\n"))
			close(p.messages)
		})
		probe.messages <- encodeFakeProcessLog("traffic-control-v1:ready")
		probe.messages <- encodeFakeTLSEvent(1, targetPID, "5151_inode_1", "read", []byte("GET /first HTTP/1.1\r\n\r\n"))

		ctx, cancel := context.WithCancel(context.Background())
		readyCh := make(chan struct{}, 1)
		done := make(chan error, 1)
		go func() {
			done <- runScriptedTLSProbe(t, ctx, s, recorder, probe, nil, time.Second, 2*time.Second, targetPID, targetID, func() { readyCh <- struct{}{} })
		}()
		<-readyCh
		cancel()
		exceeded, closeErr := shutdownWithin(func() { _ = <-done }, recorder.close, 2*time.Second)
		if exceeded || closeErr != nil {
			t.Fatalf("exceeded=%v closeErr=%v", exceeded, closeErr)
		}
		_ = finishCaptureStateReason(s, false, false, exceeded, "signal")
		if s.stats.DrainState != "unverified" || s.stats.GapCounts["ecapture/drain_unconfirmed/shutdowns"] != 1 {
			t.Fatalf("expected unverified drain, got %+v", s.stats)
		}
	})

	t.Run("drain-timeout-bounded", func(t *testing.T) {
		dir := t.TempDir()
		s, _ := openStore(dir, true)
		recorder := newRecorder(s)
		probe := newScriptedProbe(func(*scriptedProbe) {
			// Hung probe never closes messages on interrupt; drain timer must close reader.
		})
		probe.cleanExit = false // killed on reap
		probe.messages <- encodeFakeProcessLog("traffic-control-v1:ready")

		ctx, cancel := context.WithCancel(context.Background())
		readyCh := make(chan struct{}, 1)
		done := make(chan error, 1)
		go func() {
			done <- runScriptedTLSProbe(t, ctx, s, recorder, probe, nil, 80*time.Millisecond, 600*time.Millisecond, targetPID, targetID, func() { readyCh <- struct{}{} })
		}()
		<-readyCh
		started := time.Now()
		cancel()
		exceeded, closeErr := shutdownWithin(func() { _ = <-done }, recorder.close, 600*time.Millisecond)
		if exceeded || closeErr != nil || time.Since(started) > 600*time.Millisecond {
			t.Fatalf("exceeded=%v closeErr=%v elapsed=%s", exceeded, closeErr, time.Since(started))
		}
		_ = finishCaptureStateReason(s, false, false, exceeded, "duration")
		if s.stats.DrainState != "unverified" ||
			s.stats.GapCounts["ecapture/drain_timeout/shutdowns"] != 1 ||
			s.stats.GapCounts["ecapture/drain_unconfirmed/shutdowns"] != 1 {
			t.Fatalf("expected drain_timeout + unverified, got %+v", s.stats)
		}
	})

	t.Run("tail-sequence-mismatch", func(t *testing.T) {
		dir := t.TempDir()
		s, _ := openStore(dir, true)
		recorder := newRecorder(s)
		probe := newScriptedProbe(func(p *scriptedProbe) {
			// Sequences 3..5 dropped before drained marker.
			p.messages <- encodeFakeProcessLog("traffic-control-v1:drained:seq=5,dropped=3,perf_lost=0")
			close(p.messages)
		})
		probe.messages <- encodeFakeProcessLog("traffic-control-v1:ready")
		probe.messages <- encodeFakeTLSEvent(1, targetPID, "5151_inode_1", "read", []byte("GET /1 HTTP/1.1\r\n\r\n"))
		probe.messages <- encodeFakeTLSEvent(2, targetPID, "5151_inode_1", "read", []byte("GET /2 HTTP/1.1\r\n\r\n"))

		ctx, cancel := context.WithCancel(context.Background())
		readyCh := make(chan struct{}, 1)
		done := make(chan error, 1)
		go func() {
			done <- runScriptedTLSProbe(t, ctx, s, recorder, probe, nil, time.Second, 2*time.Second, targetPID, targetID, func() { readyCh <- struct{}{} })
		}()
		<-readyCh
		cancel()
		exceeded, closeErr := shutdownWithin(func() { _ = <-done }, recorder.close, 2*time.Second)
		if exceeded || closeErr != nil {
			t.Fatalf("exceeded=%v closeErr=%v", exceeded, closeErr)
		}
		_ = finishCaptureStateReason(s, false, false, exceeded, "signal")
		if s.stats.DrainState != "unverified" ||
			s.stats.GapCounts["ecapture/sequence_gap/published_events"] != 3 ||
			s.stats.GapCounts["ecapture/drain_sequence_mismatch/shutdowns"] != 1 {
			t.Fatalf("unexpected mismatch stats: %+v", s.stats)
		}
	})

	t.Run("transport-interrupted", func(t *testing.T) {
		dir := t.TempDir()
		s, _ := openStore(dir, true)
		recorder := newRecorder(s)
		probe := newScriptedProbe(nil)
		probe.readErr = errors.New("unexpected websocket reset")
		probe.messages <- encodeFakeProcessLog("traffic-control-v1:ready")
		probe.messages <- encodeFakeTLSEvent(1, targetPID, "5151_inode_1", "read", []byte("GET /1 HTTP/1.1\r\n\r\n"))
		close(probe.messages)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err := runScriptedTLSProbe(t, ctx, s, recorder, probe, nil, time.Second, 2*time.Second, targetPID, targetID, func() {})
		_ = recorder.close()
		if err == nil {
			t.Fatal("expected error on transport interruption")
		}
		_ = finishCaptureStateReason(s, false, false, false, "signal")
		if s.stats.ProbeFailures != 1 || s.stats.GapCounts["ecapture/transport_interrupted/transports"] != 1 || s.stats.DrainState != "unverified" {
			t.Fatalf("unexpected interruption stats: %+v", s.stats)
		}
		events := readRawEventsFromStream(t, filepath.Join(dir, "tls", "stream.jsonl"))
		last := events[len(events)-1]
		if last.Type != "end" || last.Reason != "transport_interrupted" {
			t.Fatalf("expected transport_interrupted end boundary, got %+v", last)
		}
	})

	t.Run("collector-abnormal-enospc", func(t *testing.T) {
		dir := t.TempDir()
		s, _ := openStore(dir, true)
		recorder := newRecorder(s)
		recorder.customSink = &failingWriteSink{failAfterBytes: 1, writeErr: syscall.ENOSPC}
		probe := newScriptedProbe(func(p *scriptedProbe) {
			close(p.messages)
		})
		probe.messages <- encodeFakeProcessLog("traffic-control-v1:ready")
		for seq := uint64(1); seq <= 128; seq++ {
			probe.messages <- encodeFakeTLSEvent(seq, targetPID, "5151_inode_1", "read", bytes.Repeat([]byte("A"), 4096))
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// Mirror main.go's fatal watcher canceling capture when s.fatal is set.
		stopFatalWatch := make(chan struct{})
		defer close(stopFatalWatch)
		go func() {
			for {
				select {
				case <-stopFatalWatch:
					return
				case <-time.After(10 * time.Millisecond):
					s.mu.Lock()
					hasFatal := s.fatal != nil
					s.mu.Unlock()
					if hasFatal {
						cancel()
						return
					}
				}
			}
		}()
		_ = runScriptedTLSProbe(t, ctx, s, recorder, probe, nil, time.Second, 2*time.Second, targetPID, targetID, func() {})
		_ = recorder.close()
		fatal := finishCaptureStateReason(s, false, false, false, "signal")
		if fatal == nil || s.stats.State != "failed" || s.stats.StopReason != "fatal_error" || s.stats.DrainState != "unverified" || !probe.reaped.Load() {
			t.Fatalf("expected failed/unverified on ENOSPC: fatal=%v reaped=%v stats=%+v",
				fatal, probe.reaped.Load(), s.stats)
		}
	})
}

type failingWriteSink struct {
	written        int
	failAfterBytes int
	writeErr       error
}

func (f *failingWriteSink) Write(p []byte) (int, error) {
	if f.written >= f.failAfterBytes {
		return 0, f.writeErr
	}
	f.written += len(p)
	return len(p), nil
}
func (f *failingWriteSink) Sync() error  { return nil }
func (f *failingWriteSink) Close() error { return nil }

func readRawEventsFromStream(t *testing.T, path string) []session.RawEvent {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lines := session.NewJSONLines(file, 4<<20)
	var out []session.RawEvent
	for {
		var ev session.RawEvent
		err := lines.Next(&ev)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("read raw stream: %v", err)
		}
		out = append(out, ev)
	}
	return out
}
