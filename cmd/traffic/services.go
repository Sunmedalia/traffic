//go:build !windows

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
	populateTargetWithListeners(root, t, nil)
}

func populateTargetWithListeners(root string, t *session.Target, tables map[string]map[string]int) {
	dir := filepath.Join(root, strconv.Itoa(t.PID))
	b, _ := os.ReadFile(filepath.Join(dir, "maps"))
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 6 && strings.HasPrefix(filepath.Base(f[5]), "libssl.so") {
			t.Library = filepath.Join(dir, "root", f[5])
			break
		}
	}
	t.Ports = listeningPortsSnapshot(root, dir, tables)
	t.State = "http-only"
	if t.Library != "" {
		t.State = "discovered"
	}
}

func discoverTargets(root, service string, pid int, library string) []session.Target {
	var dirs []string
	if pid > 0 {
		dirs = []string{filepath.Join(root, strconv.Itoa(pid))}
	} else {
		dirs, _ = filepath.Glob(filepath.Join(root, "[0-9]*"))
	}
	tables := map[string]map[string]int{}
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
		populateTargetWithListeners(root, &t, tables)
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
	Identity string
	Service  string
}

func groupFor(t session.Target, kernelScoped bool) probeGroup {
	library := t.Library
	if actual, err := filepath.EvalSymlinks(library); err == nil {
		library = actual
	}
	g := probeGroup{UID: t.UID, Library: library}
	// Never trace every root-owned process implicitly.
	if t.UID == 0 {
		if kernelScoped {
			g.Service = t.Service
		} else {
			g.PID = t.PID
			g.Identity = t.ID
		}
	}
	return g
}

func captureServices(ctx context.Context, s *Store, p *eventRecorder, bin, library, service string, pid int, javaAttach bool, javaAgent, javaHelper string, javaPID int) {
	kernelScoped := probeCapability(bin, "feature:pid_scope_v1")
	var mu sync.RWMutex
	targets := map[int]session.Target{}
	targetGroups := map[int]probeGroup{}
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
		liveJava := map[string]bool{}
		for _, target := range current {
			liveJava[target.ID] = true
		}
		mu.Lock()
		for id := range javaStates {
			if !liveJava[id] {
				delete(javaStates, id)
			}
		}
		mu.Unlock()
		eligible := map[string]bool{}
		for i := range current {
			eligible[current[i].ID] = s.checkTarget(current[i]).Status == "candidate"
			if !eligible[current[i].ID] {
				current[i].State = "unavailable"
			}
		}
		mu.Lock()
		targets = map[int]session.Target{}
		targetGroups = map[int]probeGroup{}
		for _, t := range current {
			if eligible[t.ID] {
				targets[t.PID] = t
				targetGroups[t.PID] = groupFor(t, kernelScoped)
			}
		}
		mu.Unlock()
		wanted := map[probeGroup]bool{}
		for _, t := range current {
			if eligible[t.ID] && t.Library != "" {
				wanted[groupFor(t, kernelScoped)] = true
			}
		}
		mu.Lock()
		for group := range states {
			if !wanted[group] {
				delete(states, group)
			}
		}
		mu.Unlock()
		for group, cancel := range started {
			if !wanted[group] {
				cancel()
				delete(started, group)
			}
		}
		for _, t := range current {
			if !eligible[t.ID] {
				continue
			}
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
						var err error
						for attempt := 0; attempt < 3; attempt++ {
							if attempt > 0 {
								select {
								case <-ctx.Done():
									return
								case <-time.After(time.Second << (attempt - 1)):
								}
							}
							err = captureJava(ctx, s, p, target, javaAgent, javaHelper, func() { mu.Lock(); javaStates[target.ID] = "attached"; mu.Unlock() })
							if ctx.Err() != nil || err == nil {
								break
							}
							s.gap("java-agent", target.ID, "probe_restart", "attempts", 1)
						}
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
			group := groupFor(t, kernelScoped)
			if started[group] != nil {
				continue
			}
			groupCtx, stopGroup := context.WithCancel(ctx)
			started[group] = stopGroup
			wg.Add(1)
			go func(groupCtx context.Context, g probeGroup) {
				defer wg.Done()
				accepts := func(eventPID int, reportedIdentity string) string {
					mu.RLock()
					candidate, ok := targets[eventPID]
					candidateGroup := targetGroups[eventPID]
					mu.RUnlock()
					if !ok || candidateGroup != g {
						return ""
					}
					if reportedIdentity != "" {
						if reportedIdentity == candidate.ID {
							return candidate.ID
						}
						return ""
					}
					live, err := processIdentity("/proc", eventPID)
					if err == nil && live == candidate.ID {
						return candidate.ID
					}
					return ""
				}
				snapshot := func() map[int]string {
					mu.RLock()
					defer mu.RUnlock()
					selected := map[int]string{}
					for id, target := range targets {
						if targetGroups[id] == g {
							selected[id] = target.ID
						}
					}
					return selected
				}
				setState := func(state string) {
					mu.Lock()
					states[g] = state
					identities := map[string]bool{}
					for id, target := range targets {
						if targetGroups[id] == g {
							identities[target.ID] = true
						}
					}
					s.setTLSTargetsState(identities, state)
					mu.Unlock()
				}
				for attempt := 0; attempt < 3; attempt++ {
					if attempt > 0 {
						select {
						case <-groupCtx.Done():
							return
						case <-time.After(time.Second << (attempt - 1)):
						}
					}
					setState("starting")
					err := captureTLS(groupCtx, s, p, bin, g.Library, g.PID, g.UID, accepts, snapshot, func() {
						if groupCtx.Err() == nil {
							setState("attached")
						}
					}, func(error) { setState("unavailable") })
					if groupCtx.Err() != nil {
						return
					}
					if err == nil {
						return
					}
					setState("unavailable")
					s.problem(fmt.Errorf("%s UID %d: %w", g.Library, g.UID, err))
				}
				mu.Lock()
				states[g] = "unavailable"
				mu.Unlock()
			}(groupCtx, group)
		}
		mu.RLock()
		for i := range current {
			if !eligible[current[i].ID] {
				continue
			}
			if current[i].Library != "" {
				state := states[groupFor(current[i], kernelScoped)]
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
		s.mu.Lock()
		s.stats.TLS = tlsTargetsState(current)
		s.stats.Targets = current
		s.mu.Unlock()
		mu.RUnlock()
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

func listeningPorts(root, dir string) []int { return listeningPortsSnapshot(root, dir, nil) }

// A network table belongs to a namespace, not a process. Share one immutable
// snapshot per discovery pass, but resolve FD ownership separately per process.
// Never cache across refreshes: ports and worker/library identities can change.
func listeningPortsSnapshot(root, dir string, tables map[string]map[string]int) []int {
	namespace, namespaceErr := os.Readlink(filepath.Join(dir, "ns", "net"))
	tableDir := filepath.Join(dir, "net")
	if namespaceErr != nil {
		namespace = root
		tableDir = filepath.Join(root, "net")
	}
	listeners, ok := tables[namespace]
	if !ok {
		listeners = map[string]int{}
		for _, name := range []string{"tcp", "tcp6"} {
			b, _ := os.ReadFile(filepath.Join(tableDir, name))
			for _, line := range strings.Split(string(b), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 10 || fields[3] != "0A" {
					continue
				}
				_, portText, found := strings.Cut(fields[1], ":")
				if !found {
					continue
				}
				port, err := strconv.ParseInt(portText, 16, 32)
				if err == nil {
					listeners[fields[9]] = int(port)
				}
			}
		}
		if tables != nil {
			tables[namespace] = listeners
		}
	}
	found := map[int]bool{}
	fds, _ := filepath.Glob(filepath.Join(dir, "fd", "*"))
	for _, fd := range fds {
		target, _ := os.Readlink(fd)
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			if port, ok := listeners[strings.TrimSuffix(inode, "]")]; ok {
				found[port] = true
			}
		}
	}
	ports := make([]int, 0, len(found))
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
