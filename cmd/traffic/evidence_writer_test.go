package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

type blockingEvidenceSink struct{ gate chan struct{} }

func (s *blockingEvidenceSink) Write(data []byte) (int, error) { <-s.gate; return len(data), nil }
func (s *blockingEvidenceSink) Sync() error                    { return nil }
func (s *blockingEvidenceSink) Close() error                   { return nil }

type failingEvidenceSink struct{}

func (failingEvidenceSink) Write([]byte) (int, error) { return 0, errors.New("injected disk failure") }
func (failingEvidenceSink) Sync() error               { return nil }
func (failingEvidenceSink) Close() error              { return nil }

type errnoEvidenceSink struct {
	writeErr error
	syncErr  error
	closeErr error
}

func (s errnoEvidenceSink) Write(data []byte) (int, error) {
	if s.writeErr != nil {
		return 0, &os.PathError{Op: "write", Path: "stream.jsonl", Err: s.writeErr}
	}
	return len(data), nil
}

func (s errnoEvidenceSink) Sync() error {
	if s.syncErr != nil {
		return &os.PathError{Op: "sync", Path: "stream.jsonl", Err: s.syncErr}
	}
	return nil
}

func (s errnoEvidenceSink) Close() error {
	if s.closeErr != nil {
		return &os.PathError{Op: "close", Path: "stream.jsonl", Err: s.closeErr}
	}
	return nil
}

func TestEvidenceWriterCopiesInputAndFlushesAtStop(t *testing.T) {
	s := &Store{dir: t.TempDir()}
	path := filepath.Join(s.dir, "raw.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := newEvidenceWriter(s, file, "test")
	data := []byte("{\"sequence\":1}\n")
	expected := append([]byte(nil), data...)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	for i := range data {
		data[i] = 'x'
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(saved, expected) {
		t.Fatal("queued evidence alias or missing tail", string(saved), err)
	}
	if s.rawEvidencePendingBytes() != 0 || s.stats.RawEvidenceWriters != 0 {
		t.Fatal(s.stats)
	}
}

func TestEvidenceWriterQueuesOwnedBuffersInOrder(t *testing.T) {
	for _, policy := range []evidenceBackpressurePolicy{evidenceBackpressureStrict, evidenceBackpressureDrop} {
		t.Run(string(policy), func(t *testing.T) {
			w := &evidenceWriter{
				store: &Store{}, policy: policy, queue: make(chan evidenceItem, 4),
				dataBudget: 64, controlBudget: 64, dataSlots: 4, controlSlots: 4,
				globalDataBudget: 64, globalControlReserve: 64,
			}
			source, data := []byte("source"), []byte("data")
			loss, recovery := []byte("loss"), []byte("recovery")
			if err := w.writeOwnedControl(source); err != nil {
				t.Fatal(err)
			}
			if accepted, err := w.writeOwnedData(data); err != nil || !accepted {
				t.Fatalf("data accepted=%v, err=%v", accepted, err)
			}
			if accepted, err := w.writeOwnedRecoveryAndData(loss, recovery); err != nil || !accepted {
				t.Fatalf("recovery accepted=%v, err=%v", accepted, err)
			}
			if len(w.queue) != 4 {
				t.Fatalf("queued %d records, want 4", len(w.queue))
			}
			for i, expected := range []evidenceItem{{source, true}, {data, false}, {loss, true}, {recovery, false}} {
				item := <-w.queue
				if len(item.data) != len(expected.data) || &item.data[0] != &expected.data[0] || item.control != expected.control {
					t.Fatalf("record %d was copied or enqueued out of order: %+v", i, item)
				}
			}
		})
	}
}

func TestEvidenceWriterClampsGlobalPendingSubtractions(t *testing.T) {
	s := &Store{}
	s.rawEvidencePending.Store(uint64(packEvidencePending(0, 4)))
	w := &evidenceWriter{
		store: s, policy: evidenceBackpressureDrop, queue: make(chan evidenceItem, 2),
		dataBudget: 16, controlBudget: 16, dataSlots: 2, controlSlots: 2,
		globalDataBudget: 16, globalControlReserve: 16,
		controlPending: 8, controlQueued: 1,
	}
	if accepted, err := w.writeOwnedData([]byte("data")); err != nil || !accepted {
		t.Fatalf("control bytes consumed the data budget: accepted=%v, err=%v", accepted, err)
	}
	w.release(4, 8, 1, 1)
	if evidencePending(s.rawEvidencePending.Load()).control() != 0 || s.rawEvidencePendingBytes() != 0 {
		t.Fatalf("global pending bytes underflowed: control=%d total=%d", evidencePending(s.rawEvidencePending.Load()).control(), s.rawEvidencePendingBytes())
	}
}

func TestEvidenceWriterReservesConcurrentRecoveryPairsWithinGlobalBudgets(t *testing.T) {
	const writers, budget = 32, 16
	s := &Store{dir: t.TempDir()}
	start := make(chan struct{})
	results := make(chan *evidenceWriter, writers)
	var wg sync.WaitGroup
	for range writers {
		w := &evidenceWriter{
			store: s, policy: evidenceBackpressureDrop, queue: make(chan evidenceItem, 2),
			dataBudget: budget, controlBudget: budget, dataSlots: 1, controlSlots: 1,
			globalDataBudget: budget, globalControlReserve: budget,
		}
		wg.Go(func() {
			<-start
			if accepted, err := w.writeOwnedRecoveryAndData([]byte{1}, []byte{2}); err != nil {
				t.Errorf("recovery failed: %v", err)
			} else if accepted {
				results <- w
			}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	stats := snapshotStats(s)
	if len(results) != budget || stats.RawEvidencePendingBytes != 2*budget ||
		stats.RawEvidenceHighWaterBytes != 2*budget || stats.QueueDropped != writers-budget {
		t.Fatalf("accepted=%d, pending=%d, high water=%d, shed=%d", len(results),
			stats.RawEvidencePendingBytes, stats.RawEvidenceHighWaterBytes, stats.QueueDropped)
	}
	for w := range results {
		w.release(1, 1, 1, 1)
	}
	stats = snapshotStats(s)
	if stats.RawEvidencePendingBytes != 0 || stats.RawEvidenceHighWaterBytes != 2*budget {
		t.Fatalf("after release: pending=%d, high water=%d", stats.RawEvidencePendingBytes, stats.RawEvidenceHighWaterBytes)
	}
}

func TestEvidenceWriterRejectsOverBudgetWithoutSilentSuccess(t *testing.T) {
	s := &Store{dir: t.TempDir()}
	file, err := os.Create(filepath.Join(s.dir, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	writer := newEvidenceWriter(s, file, "test")
	if n, err := writer.Write(make([]byte, (4<<20)+1)); n != 0 || !errors.Is(err, errEvidenceBackpressure) {
		t.Fatal(n, err)
	}
	if err := writer.Close(); !errors.Is(err, errEvidenceBackpressure) {
		t.Fatal("lost overflow state", err)
	}
	if s.fatal == nil || s.stats.GapCounts["test/evidence_queue_overflow/writes"] != 1 {
		t.Fatal("overflow did not stop capture", s.stats)
	}
}

func TestEvidenceWriterAcceptsQuotaBurstWithinByteBudget(t *testing.T) {
	s := &Store{dir: t.TempDir()}
	slow := &blockingEvidenceSink{gate: make(chan struct{})}
	writer := newEvidenceWriter(s, slow, "burst")
	defer func() { close(slow.gate); _ = writer.Close() }()
	data := bytes.Repeat([]byte("x"), 2048)
	// Reproduce several hundred small events arriving together after a CPU
	// quota pause. They fit comfortably inside the existing 4 MiB budget.
	for i := 0; i < 512; i++ {
		if _, err := writer.Write(data); err != nil {
			t.Fatalf("event %d rejected within byte budget: %v", i, err)
		}
	}
	s.mu.Lock()
	pending := s.rawEvidencePendingBytes()
	fatal := s.fatal
	s.mu.Unlock()
	if pending > 4<<20 || fatal != nil {
		t.Fatal("burst exceeded memory budget or stopped capture", pending, fatal)
	}
}

func TestEvidenceWriterFailureAndBoundedStop(t *testing.T) {
	s := &Store{dir: t.TempDir()}
	writer := newEvidenceWriter(s, failingEvidenceSink{}, "test")
	writer.Write([]byte("failure"))
	if err := writer.Close(); err == nil || s.fatal == nil || !s.stats.RawEvidenceDrainUnconfirmed {
		t.Fatal("disk failure hidden", err, s.stats)
	}
	slow := &blockingEvidenceSink{gate: make(chan struct{})}
	s = &Store{dir: t.TempDir()}
	writer = newEvidenceWriter(s, slow, "slow")
	writer.timeout = 20 * time.Millisecond
	writer.Write([]byte("blocked"))
	start := time.Now()
	err := writer.Close()
	if err == nil || !errors.Is(err, errEvidenceDrainTimeout) || time.Since(start) > time.Second {
		t.Fatal("stop did not respect its deadline", err)
	}
	if s.stats.GapCounts["slow/evidence_drain_timeout/shutdowns"] != 1 {
		t.Fatalf("missing drain timeout gap: %+v", s.stats.GapCounts)
	}
	close(slow.gate)
	<-writer.done
	if !s.stats.RawEvidenceDrainUnconfirmed || s.stats.RawEvidenceWriters != 0 || s.rawEvidencePendingBytes() != 0 {
		t.Fatal(s.stats)
	}
}

type finalizeFailingSink struct {
	bytes.Buffer
	syncFailure bool
}

func (s *finalizeFailingSink) Sync() error {
	if s.syncFailure {
		return errors.New("injected sync failure")
	}
	return nil
}
func (s *finalizeFailingSink) Close() error {
	if !s.syncFailure {
		return errors.New("injected close failure")
	}
	return nil
}

func TestEvidenceFinalizationFailuresStopCapture(t *testing.T) {
	for _, syncFailure := range []bool{true, false} {
		s := &Store{dir: t.TempDir()}
		writer := newEvidenceWriter(s, &finalizeFailingSink{syncFailure: syncFailure}, "finalize")
		if _, err := writer.Write([]byte("raw evidence")); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err == nil {
			t.Fatal("finalization failure hidden")
		}
		if s.fatal == nil || !s.stats.RawEvidenceDrainUnconfirmed {
			t.Fatal("failure marked successful", s.stats)
		}
	}
}

func TestEvidenceWriterDistinguishesCongestionFromENOSPCAndEIO(t *testing.T) {
	for _, policy := range []evidenceBackpressurePolicy{evidenceBackpressureStrict, evidenceBackpressureDrop} {
		for _, tc := range []struct {
			name      string
			errno     syscall.Errno
			gapReason string
			checkFn   func(error) bool
		}{
			{name: "enospc", errno: syscall.ENOSPC, gapReason: "evidence_write_enospc", checkFn: isEvidenceNoSpace},
			{name: "eio", errno: syscall.EIO, gapReason: "evidence_write_eio", checkFn: isEvidenceIOError},
		} {
			for _, phase := range []string{"write", "sync", "close"} {
				s := &Store{dir: t.TempDir()}
				sink := errnoEvidenceSink{}
				switch phase {
				case "write":
					sink.writeErr = tc.errno
				case "sync":
					sink.syncErr = tc.errno
				case "close":
					sink.closeErr = tc.errno
				}
				writer := newEvidenceWriterWithPolicy(s, sink, "raw-tls", policy)
				// Force an immediate flush (>64 KiB) during write phase so the
				// background goroutine observes writeErr before subsequent calls.
				payload := bytes.Repeat([]byte("a"), 70<<10)
				if accepted, err := writer.writeData(payload); err != nil || !accepted {
					t.Fatalf("%s/%s/%s initial write: accepted=%v err=%v", policy, tc.name, phase, accepted, err)
				}
				if phase == "write" {
					deadline := time.Now().Add(time.Second)
					for writer.failure() == nil && time.Now().Before(deadline) {
						time.Sleep(time.Millisecond)
					}
					_, nextErr := writer.writeData([]byte("after-hard-error\n"))
					if !tc.checkFn(nextErr) || !errors.Is(nextErr, tc.errno) || isEvidenceCongestion(nextErr) {
						t.Fatalf("%s/%s subsequent write misclassified: %v", policy, tc.name, nextErr)
					}
				}
				closeErr := writer.Close()
				if !tc.checkFn(closeErr) || !errors.Is(closeErr, tc.errno) || isEvidenceCongestion(closeErr) {
					t.Fatalf("%s/%s/%s close error misclassified: %v", policy, tc.name, phase, closeErr)
				}
				if s.fatal == nil || !tc.checkFn(s.fatal) || !s.stats.RawEvidenceDrainUnconfirmed {
					t.Fatalf("%s/%s/%s fatal/drain state wrong: fatal=%v stats=%+v", policy, tc.name, phase, s.fatal, s.stats)
				}
				if s.stats.GapCounts["raw-tls/"+tc.gapReason+"/errors"] != 1 {
					t.Fatalf("%s/%s/%s missing error gap: %+v", policy, tc.name, phase, s.stats.GapCounts)
				}
				if finishCaptureState(s, true, false, false) == nil || s.stats.State != "failed" || s.stats.DrainState != "unverified" || s.stats.StopReason != "fatal_error" {
					t.Fatalf("%s/%s/%s session state did not fail: %+v", policy, tc.name, phase, s.stats)
				}
			}
		}
	}
}

func TestEvidenceWriterDropPolicyReservesControlBudgetDuringGlobalSaturation(t *testing.T) {
	s := &Store{dir: t.TempDir()}
	gate := make(chan struct{})
	var saved bytes.Buffer
	sink := &gatedBufferSink{gate: gate, buf: &saved}
	cfg := evidenceWriterConfig{
		policy:               evidenceBackpressureDrop,
		dataBudget:           4096,
		controlBudget:        2048,
		dataSlots:            4,
		controlSlots:         8,
		globalDataBudget:     4096,
		globalControlReserve: 2048,
		timeout:              time.Second,
	}
	writer := newEvidenceWriterWithConfig(s, sink, "raw-tls", cfg)
	if err := writer.writeControl([]byte("ctrl:source\n")); err != nil {
		t.Fatal(err)
	}
	chunk := append(bytes.Repeat([]byte("d"), 1023), '\n')
	acceptedCount, shedCount := 0, 0
	for i := 0; i < 10; i++ {
		accepted, err := writer.writeData(chunk)
		if err != nil {
			t.Fatal(err)
		}
		if accepted {
			acceptedCount++
		} else {
			shedCount++
		}
	}
	if acceptedCount != 4 || shedCount != 6 {
		t.Fatalf("expected 4 accepted and 6 shed, got accepted=%d shed=%d", acceptedCount, shedCount)
	}
	// Data budget and global data budget are now 100% saturated, yet control
	// records (loss, end) must still be accepted in order.
	if err := writer.writeControl([]byte("ctrl:loss\n")); err != nil {
		t.Fatalf("control loss rejected during data saturation: %v", err)
	}
	if err := writer.writeControl([]byte("ctrl:end\n")); err != nil {
		t.Fatalf("control end rejected during data saturation: %v", err)
	}
	close(gate)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if s.fatal != nil || s.rawEvidenceQueueDropped.Load() != 6 || s.stats.GapCounts["raw-tls/evidence_queue_shed/events"] != 6 {
		t.Fatalf("unexpected stats: fatal=%v stats=%+v", s.fatal, s.stats)
	}
	lines := bytes.Split(bytes.TrimSpace(saved.Bytes()), []byte("\n"))
	if len(lines) != 7 || string(lines[0]) != "ctrl:source" || string(lines[5]) != "ctrl:loss" || string(lines[6]) != "ctrl:end" {
		t.Fatalf("control ordering broken: %q", saved.String())
	}
}

type gatedBufferSink struct {
	gate chan struct{}
	buf  *bytes.Buffer
}

func (s *gatedBufferSink) Write(data []byte) (int, error) {
	<-s.gate
	return s.buf.Write(data)
}
func (s *gatedBufferSink) Sync() error  { return nil }
func (s *gatedBufferSink) Close() error { return nil }
