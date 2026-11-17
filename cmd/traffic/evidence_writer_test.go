package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
	if s.stats.RawEvidencePendingBytes != 0 || s.stats.RawEvidenceWriters != 0 {
		t.Fatal(s.stats)
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
	pending := s.stats.RawEvidencePendingBytes
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
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("stop did not respect its deadline", err)
	}
	close(slow.gate)
	<-writer.done
	if !s.stats.RawEvidenceDrainUnconfirmed || s.stats.RawEvidenceWriters != 0 {
		t.Fatal(s.stats)
	}
}
