package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/Sunmedalia/traffic/internal/session"
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
	if s.iisAttached && !s.iisPlaintext.Load() && s.stats.ProbeSendMatches > 0 && s.stats.ProbeUnmatchedCompletions > 0 {
		s.stats.AttachWindowSuspect = true
		s.stats.Errors = append(s.stats.Errors, "IIS probe attached but observed no request-side plaintext; responses were hooked and receives were not (attach window). No completed request buffer was recovered; inspect the probe diagnostics. probe_send_matches counts responses only and does not prove request capture.")
	}
	if requirePlaintext && (!s.iisAttached || !s.iisPlaintext.Load()) && s.fatal == nil {
		s.fatal = errors.New("--require-plaintext: no IIS request-side plaintext was recorded")
		s.stats.Errors = append(s.stats.Errors, s.fatal.Error())
	}
}

func applyIISProbeSummary(s *Store, values map[string]any) {
	receive := diagCount(values, "receive_matches")
	recovered := diagCount(values, "recovered_receives")
	body := diagCount(values, "body_matches")
	send := diagCount(values, "send_matches")
	unmatched := diagCount(values, "unmatched_completions")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.ProbeReceiveMatches += receive
	s.stats.ProbeRecoveredReceives += recovered
	s.stats.ProbeBodyMatches += body
	s.stats.ProbeSendMatches += send
	s.stats.ProbeUnmatchedCompletions += unmatched
	if s.iisAttached && !s.iisPlaintext.Load() && receive == 0 && send > 0 && unmatched > 0 {
		s.stats.AttachWindowSuspect = true
	}
}

func parseIISBindingPorts(data []byte, protocols ...string) []int {
	if len(data) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, proto := range protocols {
		allowed[strings.ToLower(proto)] = true
	}
	var config struct {
		Bindings []struct {
			Protocol string `xml:"protocol,attr"`
			Info     string `xml:"bindingInformation,attr"`
		} `xml:"system.applicationHost>sites>site>bindings>binding"`
	}
	if xml.Unmarshal(data, &config) != nil {
		return nil
	}
	set := map[int]bool{}
	for _, binding := range config.Bindings {
		if !allowed[strings.ToLower(binding.Protocol)] {
			continue
		}
		parts := strings.Split(binding.Info, ":")
		if len(parts) < 3 {
			continue
		}
		port, err := strconv.Atoi(parts[len(parts)-2])
		if err == nil && port > 0 && port <= 65535 {
			set[port] = true
		}
	}
	var ports []int
	for port := range set {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

// iisPortsMatchHTTPS returns false only when IIS bindings are known and none of
// the selected capture ports correspond to an HTTPS binding.
func iisPortsMatchHTTPS(allPorts, httpsPorts []int, selected map[int]bool) bool {
	if len(allPorts) == 0 {
		return true
	}
	if len(httpsPorts) == 0 {
		return false
	}
	if len(selected) == 0 {
		return true
	}
	for _, port := range httpsPorts {
		if selected[port] {
			return true
		}
	}
	return false
}

func recordWindowsProbeExit(s *Store, targetID string, dataDrained, hooksRemoved, scriptUnloaded, transportDetached bool) {
	runtimeState := "clean_detach"
	if !hooksRemoved {
		runtimeState = "hooks_not_restored"
		s.gap("windows-probe", targetID, "hooks_not_restored", "shutdowns", 1)
	} else if !scriptUnloaded || !transportDetached {
		runtimeState = "hooks_removed_runtime_lingering"
		s.gap("windows-probe", targetID, "runtime_unload_incomplete", "shutdowns", 1)
	}
	s.recordProbeExit(targetID, session.ProbeExit{
		HookBased:         true,
		DataDrained:       dataDrained,
		HooksRemoved:      hooksRemoved,
		ScriptUnloaded:    scriptUnloaded,
		TransportDetached: transportDetached,
		RuntimeState:      runtimeState,
	})
}
