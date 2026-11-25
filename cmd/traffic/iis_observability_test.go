package main

import (
	"github.com/Sunmedalia/traffic/internal/session"
	"strings"
	"testing"
)

func TestAttachWindowBecomesVisible(t *testing.T) {
	s := &Store{}
	s.iisAttached = true
	applyIISProbeSummary(s, map[string]any{
		"receive_matches": 0, "body_matches": 0, "send_matches": 3, "unmatched_completions": 41,
	})
	if !s.stats.AttachWindowSuspect || s.stats.PlaintextObserved {
		t.Fatalf("send-only matches must be an attach-window suspect, got %+v", s.stats)
	}
	if s.stats.ProbeSendMatches != 3 || s.stats.ProbeReceiveMatches != 0 || s.stats.ProbeUnmatchedCompletions != 41 {
		t.Fatalf("counters were mixed: %+v", s.stats)
	}
	finishIISObservability(s, true)
	if s.fatal == nil || !strings.Contains(s.fatal.Error(), "--require-plaintext") {
		t.Fatalf("require-plaintext must fail a zero-request attach, fatal=%v", s.fatal)
	}
	joined := strings.Join(s.stats.Errors, "\n")
	if !strings.Contains(joined, "attach window") || !strings.Contains(joined, "probe_send_matches") {
		t.Fatalf("status errors do not explain the window: %s", joined)
	}
}

func TestReceiveHookDoesNotProveRecordedPlaintext(t *testing.T) {
	s := &Store{iisAttached: true}
	applyIISProbeSummary(s, map[string]any{"receive_matches": 12, "send_matches": 12, "recovered_receives": 10})
	if s.stats.ProbeRecoveredReceives != 10 {
		t.Fatalf("recovered receive count missing: %+v", s.stats)
	}
	finishIISObservability(s, true)
	if s.fatal == nil || s.stats.PlaintextObserved {
		t.Fatal("hook matches accepted without recorded plaintext")
	}
	s.fatal = nil
	s.stats.Errors = nil
	s.iisPlaintext.Store(true)
	s.stats.PlaintextObserved = true
	finishIISObservability(s, true)
	if s.fatal != nil {
		t.Fatal(s.fatal)
	}
}

func TestNginxPlaintextDoesNotSatisfyIISRequirement(t *testing.T) {
	s := &Store{iisAttached: true, stats: session.Stats{PlaintextObserved: true}}
	applyIISProbeSummary(s, map[string]any{"send_matches": 3, "unmatched_completions": 10})
	if !s.stats.AttachWindowSuspect {
		t.Fatal("nginx plaintext masked the IIS attach window")
	}
	finishIISObservability(s, true)
	if s.fatal == nil || !strings.Contains(s.fatal.Error(), "--require-plaintext") {
		t.Fatalf("nginx plaintext satisfied the IIS request requirement: %v", s.fatal)
	}
}

func TestRequirePlaintextRejectsMissingIISProbe(t *testing.T) {
	s := &Store{}
	finishIISObservability(s, true)
	if s.fatal == nil {
		t.Fatal("require-plaintext silently passed without IIS")
	}
}

func TestUnmatchedIOWithoutSendIsNotAttachWindow(t *testing.T) {
	s := &Store{}
	s.iisAttached = true
	applyIISProbeSummary(s, map[string]any{"receive_matches": 0, "send_matches": 0, "unmatched_completions": 40})
	finishIISObservability(s, false)
	if s.stats.AttachWindowSuspect || len(s.stats.Errors) != 0 || s.fatal != nil {
		t.Fatalf("unrelated I/O completions must not be reported as the attach window: %+v fatal=%v", s.stats, s.fatal)
	}
}

func TestProbeGapKeepsRunningTotal(t *testing.T) {
	dir := t.TempDir()
	s := &Store{dir: dir}
	s.noteProbeGap("pid", "unmatched_completion", "unknown", 1)
	s.noteProbeGap("pid", "unmatched_completion", "unknown", 8)
	s.noteProbeGap("pid", "unmatched_completion", "unknown", 8)
	if got := s.stats.GapCounts["iis-httpapi/unmatched_completion_unknown/completions"]; got != 8 {
		t.Fatalf("running totals must not be summed, got %d", got)
	}
}

func TestRawIISRequestSatisfiesPlaintextRequirement(t *testing.T) {
	s := &Store{dir: t.TempDir(), iisAttached: true, stats: Stats{PlaintextObserved: true, AttachWindowSuspect: true}}
	s.plaintextObserved.Store(true) // OpenSSL plaintext has already been observed.
	recorder := newRecorder(s)
	if err := recorder.iis("generation", session.Target{ID: "42:start", PID: 42}, iisEvent{Type: "request", ID: "request", Method: "GET", URL: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.close(); err != nil {
		t.Fatal(err)
	}
	finishIISObservability(s, true)
	if s.fatal != nil || !s.iisPlaintext.Load() || s.stats.AttachWindowSuspect ||
		!s.stats.PlaintextObserved || s.stats.Transactions != 0 || s.stats.TLSRequests != 0 {
		t.Fatal("raw request was decoded or rejected", s.stats, s.fatal)
	}
	failed := &Store{dir: t.TempDir(), iisAttached: true}
	closed := newRecorder(failed)
	closed.close()
	if err := closed.iis("generation", session.Target{}, iisEvent{Type: "request"}); err == nil {
		t.Fatal("closed recorder accepted request")
	}
	if failed.stats.PlaintextObserved {
		t.Fatal("failed raw write marked plaintext observed")
	}
}
