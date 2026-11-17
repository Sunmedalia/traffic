package main

import (
	"encoding/json"
	"errors"
)

func diagCount(values map[string]any, name string) uint64 {
	if values == nil {
		return 0
	}
	var number int64
	switch value := values[name].(type) {
	case float64:
		number = int64(value)
	case int:
		number = int64(value)
	case int64:
		number = value
	case uint64:
		return value
	case json.Number:
		parsed, err := value.Int64()
		if err != nil {
			return 0
		}
		number = parsed
	default:
		return 0
	}
	if number < 0 {
		return 0
	}
	return uint64(number)
}

// finishIISObservability turns a silent zero-plaintext stop into an explicit error.
// Send matches alone are not evidence that requests were captured.
func finishIISObservability(s *Store, requirePlaintext bool) {
	// Send matches with zero receives is the measured attach window: the
	// response went through the hook, the pre-posted receive did not.
	// Unmatched completions alone are not that window. w3wp completes I/O
	// that this probe never registered.
	if s.iisAttached && !s.stats.PlaintextObserved && s.stats.ProbeSendMatches > 0 && s.stats.ProbeUnmatchedCompletions > 0 {
		s.stats.AttachWindowSuspect = true
		s.stats.Errors = append(s.stats.Errors, "IIS probe attached but observed no request-side plaintext; responses were hooked and receives were not (attach window). Warm the site with more requests than the pre-posted receive count before judging plaintext support. probe_send_matches counts responses only and does not prove request capture.")
	}
	if requirePlaintext && (!s.iisAttached || !s.stats.PlaintextObserved) && s.fatal == nil {
		s.fatal = errors.New("--require-plaintext: no IIS request-side plaintext was recorded")
		s.stats.Errors = append(s.stats.Errors, s.fatal.Error())
	}
}

func applyIISProbeSummary(s *Store, values map[string]any) {
	receive := diagCount(values, "receive_matches")
	body := diagCount(values, "body_matches")
	send := diagCount(values, "send_matches")
	unmatched := diagCount(values, "unmatched_completions")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.ProbeReceiveMatches += receive
	s.stats.ProbeBodyMatches += body
	s.stats.ProbeSendMatches += send
	s.stats.ProbeUnmatchedCompletions += unmatched
	if s.iisAttached && !s.stats.PlaintextObserved && receive == 0 && send > 0 && unmatched > 0 {
		s.stats.AttachWindowSuspect = true
	}
}
