package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

// A process start time is part of its identity because Linux reuses PIDs.
func processTarget(root string, pid int) (session.Target, error) {
	t := session.Target{PID: pid}
	dir := filepath.Join(root, strconv.Itoa(pid))
	var err error
	t.ID, err = processIdentity(root, pid)
	if err != nil {
		return t, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return t, err
	}
	t.UID = -1
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Gid:") {
			f := strings.Fields(line)
			if len(f) > 1 {
				t.GID, _ = strconv.Atoi(f[1])
			}
		}
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) > 1 {
				t.UID, _ = strconv.Atoi(f[1])
			}
		}
	}
	if t.UID < 0 {
		return t, fmt.Errorf("missing process UID")
	}
	b, err = os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil {
		return t, err
	}
	cmd := strings.ReplaceAll(string(b), "\x00", " ")
	exe, _ := os.Readlink(filepath.Join(dir, "exe"))
	name := filepath.Base(exe)
	switch {
	case strings.Contains(cmd, "nginx: worker"):
		t.Service = "nginx"
	case name == "apache2" || name == "httpd":
		t.Service = "apache"
	case strings.Contains(cmd, "org.apache.catalina.startup.Bootstrap"):
		t.Service = "tomcat"
	default:
		t.Service = "unknown"
	}

	return t, nil
}

func populateTarget(root string, t *session.Target) {
	dir := filepath.Join(root, strconv.Itoa(t.PID))
	b, _ := os.ReadFile(filepath.Join(dir, "maps"))
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 6 && strings.HasPrefix(filepath.Base(f[5]), "libssl.so") {
			t.Library = filepath.Join(dir, "root", f[5])
			break
		}
	}
	t.Ports = listeningPorts(root, dir)
	t.State = "http-only"
	if t.Library != "" {
		t.State = "discovered"
	}
}

func discoverTargets(root, service string, pid int, library string) []session.Target {
	dirs, _ := filepath.Glob(filepath.Join(root, "[0-9]*"))
	var targets []session.Target
	for _, dir := range dirs {
		id, err := strconv.Atoi(filepath.Base(dir))
		if err != nil || (pid > 0 && id != pid) {
			continue
		}
		t, err := processTarget(root, id)
		if err != nil {
			continue
		}
		if pid == 0 && (t.Service == "unknown" || (service != "auto" && service != t.Service)) {
			continue
		}
		populateTarget(root, &t)
		if service == "openssl" && pid > 0 {
			t.Service = "openssl"
		}
		if library != "" {
			t.Library = library
			t.State = "discovered"
		}
		targets = append(targets, t)
	}
	if pid == 0 {
		workers := map[string]bool{}
		for _, t := range targets {
			if t.UID != 0 {
				workers[t.Service] = true
			}
		}
		filtered := targets[:0]
		for _, t := range targets {
			if t.UID == 0 && workers[t.Service] {
				continue
			}
			filtered = append(filtered, t)
		}
		targets = filtered
	}
	return targets
}

type probeGroup struct {
	UID, PID int
	Library  string
}

func groupFor(t session.Target) probeGroup {
	library := t.Library
	if actual, err := filepath.EvalSymlinks(library); err == nil {
		library = actual
	}
	g := probeGroup{UID: t.UID, Library: library}
	// Never trace every root-owned process implicitly.
	if t.UID == 0 {
		g.PID = t.PID
	}
	return g
}

func captureServices(ctx context.Context, s *Store, p *HTTPProcessor, bin, library, service string, pid int, javaAttach bool, javaAgent, javaHelper string, javaPID int) {
	var mu sync.RWMutex
	targets := map[int]session.Target{}
	states := map[probeGroup]string{}
	started := map[probeGroup]context.CancelFunc{}
	javaStates := map[string]string{}
	var wg sync.WaitGroup
	refresh := func() {
		current := discoverTargets("/proc", service, pid, library)
		selected := current[:0]
		for _, target := range current {
			inScope := pid > 0 || target.PID == javaPID
			for _, port := range target.Ports {
				if capturePorts[port] {
					inScope = true
					break
				}
			}
			if inScope {
				selected = append(selected, target)
			}
		}
		current = selected
		mu.Lock()
		targets = map[int]session.Target{}
		for _, t := range current {
			targets[t.PID] = t
		}
		mu.Unlock()
		wanted := map[probeGroup]bool{}
		for _, t := range current {
			if t.Library != "" {
				wanted[groupFor(t)] = true
			}
		}
		for group, cancel := range started {
			if !wanted[group] {
				cancel()
				delete(started, group)
			}
		}
		for _, t := range current {
			if t.Service == "tomcat" && javaAttach && (javaPID == 0 || t.PID == javaPID) && t.Library == "" {
				mu.Lock()
				_, launched := javaStates[t.ID]
				if !launched {
					javaStates[t.ID] = "starting"
				}
				mu.Unlock()
				if !launched {
					wg.Add(1)
					go func(target session.Target) {
						defer wg.Done()
						err := captureJava(ctx, s, p, target, javaAgent, javaHelper, func() { mu.Lock(); javaStates[target.ID] = "attached"; mu.Unlock() })
						state := "stopped"
						if err != nil {
							state = "unavailable"
							s.problem(err)
						}
						mu.Lock()
						javaStates[target.ID] = state
						mu.Unlock()
					}(t)
				}
				continue
			}
			if t.Library == "" {
				continue
			}
			group := groupFor(t)
			if started[group] != nil {
				continue
			}
			groupCtx, stopGroup := context.WithCancel(ctx)
			started[group] = stopGroup
			wg.Add(1)
			go func(groupCtx context.Context, g probeGroup) {
				defer wg.Done()
				accepts := func(eventPID int) bool {
					mu.RLock()
					candidate, ok := targets[eventPID]
					mu.RUnlock()
					if !ok || groupFor(candidate) != g {
						return false
					}
					live, err := processIdentity("/proc", eventPID)
					return err == nil && live == candidate.ID
				}
				for attempt := 0; attempt < 2; attempt++ {
					mu.Lock()
					states[g] = "starting"
					mu.Unlock()
					err := captureTLS(groupCtx, s, p, bin, g.Library, g.PID, g.UID, accepts, func() { mu.Lock(); states[g] = "attached"; mu.Unlock() })
					if groupCtx.Err() != nil {
						return
					}
					if err == nil {
						return
					}
					s.problem(fmt.Errorf("%s UID %d: %w", g.Library, g.UID, err))
				}
				mu.Lock()
				states[g] = "unavailable"
				mu.Unlock()
			}(groupCtx, group)
		}
		mu.RLock()
		for i := range current {
			if current[i].Library != "" {
				state := states[groupFor(current[i])]
				if state == "" {
					state = "starting"
				}
				current[i].State = state
			} else if current[i].Service == "tomcat" {
				current[i].State = "java-probe-required"
				if javaAttach && (javaPID == 0 || current[i].PID == javaPID) {
					current[i].State = javaStates[current[i].ID]
				}
			}
		}
		mu.RUnlock()
		attached, unavailable := 0, 0
		for _, t := range current {
			if t.State == "attached" {
				attached++
			}
			if t.State == "unavailable" {
				unavailable++
			}
		}
		s.mu.Lock()
		if attached > 0 && unavailable > 0 {
			s.stats.TLS = "partial"
		} else if attached > 0 {
			s.stats.TLS = "attached"
		} else if unavailable > 0 {
			s.stats.TLS = "unavailable"
		}
		s.stats.Targets = current
		s.mu.Unlock()
	}
	refresh()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func listeningPorts(root, dir string) []int {
	inodes := map[string]bool{}
	fds, _ := filepath.Glob(filepath.Join(dir, "fd", "*"))
	for _, fd := range fds {
		target, _ := os.Readlink(fd)
		if strings.HasPrefix(target, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	found := map[int]bool{}
	for _, name := range []string{"tcp", "tcp6"} {
		b, _ := os.ReadFile(filepath.Join(root, "net", name))
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "0A" || !inodes[f[9]] {
				continue
			}
			parts := strings.Split(f[1], ":")
			if len(parts) != 2 {
				continue
			}
			port, err := strconv.ParseInt(parts[1], 16, 32)
			if err == nil {
				found[int(port)] = true
			}
		}
	}
	ports := []int{}
	for port := range found {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func processIdentity(root string, pid int) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	end := strings.LastIndex(string(b), ")")
	if end < 0 {
		return "", fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(string(b)[end+1:])
	if len(fields) < 20 {
		return "", fmt.Errorf("short process stat")
	}
	return fmt.Sprintf("%d:%s", pid, fields[19]), nil
}
