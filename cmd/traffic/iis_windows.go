package main

import (
	"bufio"
	"context"
	"encoding/json"

	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

func captureWindowsProbe(ctx context.Context, s *Store, p *HTTPProcessor, target session.Target, attached func()) (result error) {
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
	raw, err := os.OpenFile(filepath.Join(s.dir, "tls", backend+"-"+tag+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer raw.Close()
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
		"--ports", strings.Join(ports, ","), "--request-limit", strconv.Itoa(requestLimit), "--response-limit", strconv.Itoa(responseLimit)}
	if backend == "openssl" {
		if opensslProfile != "" {
			args = append(args, "--profile", opensslProfile)
		}
		if target.Library != "" {
			args = append(args, "--library", target.Library)
		}
	}
	command := exec.Command(iisPython, args...)
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
	assembler := &iisAssembler{store: s, target: target}
	frames := &Frames{}
	stopExpiry := frames.startExpiry(ctx, p)
	defer stopExpiry()
	openssl := &opensslAssembler{processor: p, frames: frames, prefix: fmt.Sprintf("windows-openssl-%d/%s/", serial.Add(1), target.ID), pid: target.PID}
	defer func() {
		if err := openssl.close(""); result == nil && err != nil {
			result = err
		}
	}()
	defer func() {
		if err := assembler.finish(); result == nil && err != nil {
			result = err
		}
	}()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if _, err := raw.Write(append(append([]byte(nil), line...), '\n')); err != nil {
			return err
		}
		var message struct {
			Type         string          `json:"type"`
			Message      string          `json:"message"`
			Description  string          `json:"description"`
			HooksRemoved bool            `json:"hooks_removed"`
			Payload      json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(line, &message); err != nil {
			return fmt.Errorf("Windows TLS helper protocol: %w", err)
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
		if event.Type == "error" {
			return fmt.Errorf("Windows TLS probe: %s", event.Message)
		}
		if event.Type == "ready" {
			if event.Protocol != protocol {
				return fmt.Errorf("Windows TLS helper protocol version mismatch")
			}
			attached()
			if backend == "iis" {
				s.problem(fmt.Errorf("IIS dynamic attach cannot recover receive calls posted before attachment; startup requests may be missed"))
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
			if err := assembler.ingest(apiEvent); err != nil {
				return err
			}
			continue
		}
		if err := openssl.ingest(event); err != nil {
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

func captureWindowsServices(ctx context.Context, s *Store, p *HTTPProcessor, service string, pid int, library string) {
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
			child, cancel := context.WithCancel(ctx)
			worker := &worker{cancel: cancel, state: "starting"}
			workers[target.ID] = worker
			running.Add(1)
			go func(target session.Target) {
				defer running.Done()
				err := captureWindowsProbe(child, s, p, target, func() { mu.Lock(); worker.state = "attached"; mu.Unlock() })
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
		if attached > 0 {
			state = "attached"
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
