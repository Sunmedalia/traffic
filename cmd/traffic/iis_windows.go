package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

func captureWindowsProbe(ctx context.Context, s *Store, p *eventRecorder, target session.Target, attached func()) (result error) {
	backend, helper, protocol := "iis", iisProbe, "traffic-iis-v1"
	if target.Service != "iis" {
		backend, helper, protocol = "openssl", opensslProbe, "traffic-openssl-v1"
	}
	for _, name := range []string{"logs", "tls"} {
		if err := os.MkdirAll(filepath.Join(s.dir, name), 0700); err != nil {
			return err
		}
	}
	tag := strings.ReplaceAll(target.ID, ":", "-")
	log, err := os.OpenFile(filepath.Join(s.dir, "logs", backend+"-"+tag+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	var ports []string
	for port := range capturePorts {
		ports = append(ports, strconv.Itoa(port))
	}
	sort.Strings(ports)
	args := []string{helper, "--plaintext", "--control-stdin", "--duration", "0",
		"--pid", strconv.Itoa(target.PID), "--out", "-", "--runtime-dir", iisRuntime,
		"--ports", strings.Join(ports, ","), "--request-limit", "0", "--response-limit", "0"}
	if backend == "openssl" {
		if opensslProfile != "" {
			args = append(args, "--profile", opensslProfile)
		}
		if target.Library != "" {
			args = append(args, "--library", target.Library)
		}
	}
	command := exec.Command(iisPython, args...)
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	command.Stderr = log
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	finished := make(chan struct{})
	readFinished := make(chan struct{})
	var readOnce sync.Once
	finishRead := func() { readOnce.Do(func() { close(readFinished) }) }
	var waitError error
	go func() { <-readFinished; waitError = command.Wait(); close(finished) }()
	var stopOnce sync.Once
	var detached atomic.Bool
	stop := func() {
		stopOnce.Do(func() {
			stdin.Write([]byte("stop\n"))
			stdin.Close()
			select {
			case <-finished:
			case <-time.After(15 * time.Second):
				if !detached.Load() {
					s.problem(fmt.Errorf("Windows TLS helper did not confirm detach before the stop deadline"))
				}
				command.Process.Kill()
				<-finished
			}
		})
	}
	defer stop()
	defer finishRead()
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-finished:
		}
	}()
	source := fmt.Sprintf("windows-%s-%d/%s", backend, serial.Add(1), target.ID)
	defer func() {
		if err := p.record(source, backend, target, session.RawEvent{Type: "end"}); result == nil && err != nil {
			result = err
		}
	}()
	var lastSequence uint64
	var probeDrain bool
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		var message struct {
			Type              string          `json:"type"`
			Message           string          `json:"message"`
			Description       string          `json:"description"`
			HooksRemoved      bool            `json:"hooks_removed"`
			LastSequence      *uint64         `json:"last_sequence"`
			QueueDropped      uint64          `json:"queue_dropped"`
			ScriptUnloaded    bool            `json:"script_unloaded"`
			TransportDetached bool            `json:"transport_detached"`
			Diagnostics       map[string]any  `json:"diagnostics"`
			Payload           json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(line, &message); err != nil {
			return fmt.Errorf("Windows TLS helper protocol: %w", err)
		}
		if message.Type == "summary" && message.LastSequence != nil {
			probeDrain = lastSequence == *message.LastSequence
		}
		if message.Type == "summary" && backend == "iis" {
			applyIISProbeSummary(s, message.Diagnostics)
		}
		if message.Type == "host_summary" {
			s.recordProbeExit(target.ID, session.ProbeExit{DataDrained: probeDrain && message.QueueDropped == 0, HooksRemoved: message.HooksRemoved, ScriptUnloaded: message.ScriptUnloaded, TransportDetached: message.TransportDetached, RuntimeState: "inspect hooks, script and transport separately"})
		}
		if message.Type == "attach_error" || message.Type == "error" {
			return fmt.Errorf("Windows TLS helper: %s %s", message.Message, message.Description)
		}
		if (message.Type == "summary" || message.Type == "host_summary") && message.HooksRemoved {
			detached.Store(true)
		}
		if message.Type != "send" {
			continue
		}
		var event opensslEvent
		if err := json.Unmarshal(message.Payload, &event); err != nil {
			return err
		}
		if event.Sequence > 0 {
			if lastSequence > 0 && event.Sequence != lastSequence+1 {
				reason, unit, count := sequenceDiscontinuity(lastSequence, event.Sequence)
				s.gap(backend, target.ID, reason, unit, count)
				if err := p.record(source, backend, target, session.RawEvent{Type: "loss", Reason: reason, Unit: unit, Count: count}); err != nil {
					return err
				}
			}

			lastSequence = event.Sequence
		}
		if event.Type == "error" {
			return fmt.Errorf("Windows TLS probe: %s", event.Message)
		}
		if event.Type == "ready" {
			if event.Protocol != protocol {
				return fmt.Errorf("Windows TLS helper protocol version mismatch")
			}
			attached()
			if backend == "iis" {
				s.mu.Lock()
				s.iisAttached = true
				s.mu.Unlock()
				fmt.Fprintf(os.Stderr, "IIS 探针已附加，已启用完成通知中的请求缓冲区恢复，无需预热。停止后检查 plaintext_observed、probe_receive_matches 和 probe_recovered_receives；附加前已完成的请求及无法识别的完成上下文仍不保证覆盖。\n")
			}
			continue
		}
		live, err := processIdentity("", target.PID)
		if err != nil || live != target.ID {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("Windows TLS target identity changed")
		}
		if backend == "iis" {
			var apiEvent iisEvent
			if err := json.Unmarshal(message.Payload, &apiEvent); err != nil {
				return err
			}
			if err := p.iis(source, target, apiEvent); err != nil {
				return err
			}

			continue
		}
		if err := p.openssl(source, backend, target, event); err != nil {
			return err
		}

	}
	if err := scanner.Err(); err != nil {
		return err
	}
	finishRead()
	<-finished
	if ctx.Err() != nil {
		return nil
	}
	if waitError != nil {
		return fmt.Errorf("Windows TLS helper exited: %w; see %s", waitError, log.Name())
	}
	return fmt.Errorf("Windows TLS helper stopped unexpectedly; see %s", log.Name())
}

func captureWindowsServices(ctx context.Context, s *Store, p *eventRecorder, service string, pid int, library string) {
	type worker struct {
		cancel context.CancelFunc
		state  string
	}
	workers := make(map[string]*worker)
	var mu sync.Mutex
	var running sync.WaitGroup
	defer func() {
		for _, worker := range workers {
			worker.cancel()
		}
		running.Wait()
	}()
	refresh := func() {
		targets := discoverTargets("", service, pid, library)
		wanted := make(map[string]bool)
		for _, target := range targets {
			wanted[target.ID] = true
		}
		for id, worker := range workers {
			if !wanted[id] {
				worker.cancel()
				delete(workers, id)
			}
		}
		for _, target := range targets {
			if workers[target.ID] != nil {
				continue
			}
			if (target.Service == "iis" && iisProbe == "") || (target.Service != "iis" && opensslProbe == "") {
				workers[target.ID] = &worker{cancel: func() {}, state: "http-only"}
				continue
			}
			if s.checkTarget(target).Status != "candidate" {
				workers[target.ID] = &worker{cancel: func() {}, state: "unavailable"}
				continue
			}
			child, cancel := context.WithCancel(ctx)
			worker := &worker{cancel: cancel, state: "starting"}
			workers[target.ID] = worker
			running.Add(1)
			go func(target session.Target) {
				defer running.Done()
				var err error
				for attempt := 0; attempt < 3; attempt++ {
					if attempt > 0 {
						select {
						case <-child.Done():
							return
						case <-time.After(time.Second << (attempt - 1)):
						}
					}
					mu.Lock()
					worker.state = "starting"
					mu.Unlock()
					err = captureWindowsProbe(child, s, p, target, func() { mu.Lock(); worker.state = "attached"; mu.Unlock() })
					if child.Err() != nil || err == nil {
						break
					}
					s.problem(fmt.Errorf("%s PID %d probe attempt %d: %w", target.Service, target.PID, attempt+1, err))
					s.gap("windows-probe", target.ID, "probe_restart", "attempts", 1)
				}
				mu.Lock()
				worker.state = "stopped"
				if err != nil {
					worker.state = "unavailable"
				}
				mu.Unlock()
				if err != nil {
					s.problem(fmt.Errorf("%s PID %d: %w", target.Service, target.PID, err))
				}
			}(target)
		}
		attached, unavailable := 0, 0
		mu.Lock()
		for index := range targets {
			targets[index].State = workers[targets[index].ID].state
			if targets[index].State == "attached" {
				attached++
			}
			if targets[index].State == "unavailable" {
				unavailable++
			}
		}
		mu.Unlock()
		state := "starting"
		if len(targets) == 0 {
			state = "no-targets"
		}
		if attached > 0 {
			state = "attached"
			if attached < len(targets) {
				state = "partial"
			}
		}
		if unavailable > 0 {
			state = "unavailable"
			if attached > 0 {
				state = "partial"
			}
		}
		s.mu.Lock()
		s.stats.Targets = targets
		s.stats.TLS = state
		s.mu.Unlock()
	}
	refresh()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}
