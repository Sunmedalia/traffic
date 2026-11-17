package main

import (
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

func TestReceiveMatchClearsSuspect(t *testing.T) {
	s := &Store{}
	s.iisAttached = true
	applyIISProbeSummary(s, map[string]any{"receive_matches": 12, "send_matches": 12, "unmatched_completions": 10})
	if !s.stats.PlaintextObserved || s.stats.AttachWindowSuspect {
		t.Fatalf("a receive match is observed plaintext, got %+v", s.stats)
	}
	finishIISObservability(s, false)
	if s.fatal != nil || len(s.stats.Errors) != 0 {
		t.Fatalf("a receive match must not be labeled an attach window: fatal=%v errors=%v", s.fatal, s.stats.Errors)
	}
	// The flag follows saved requests. A hook match that never reached the index still fails.
	finishIISObservability(s, true)
	if s.fatal == nil {
		t.Fatal("require-plaintext follows tls_requests, not receive_matches alone")
	}
	s.fatal = nil
	s.stats.Errors = nil
	s.stats.TLSRequests = 12
	finishIISObservability(s, true)
	if s.fatal != nil || len(s.stats.Errors) != 0 {
		t.Fatalf("saved plaintext must satisfy require-plaintext: fatal=%v errors=%v", s.fatal, s.stats.Errors)
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
