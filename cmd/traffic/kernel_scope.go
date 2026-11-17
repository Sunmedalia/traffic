package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type kernelScopeSnapshot func() map[int]string
type kernelScopePID struct {
	PID        uint32 `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
}
type kernelScopeDocument struct {
	Version int              `json:"schema_version"`
	PIDs    []kernelScopePID `json:"pids"`
	Ports   []uint32         `json:"ports"`
}
type kernelScopeFile struct {
	path     string
	snapshot kernelScopeSnapshot
	ports    []uint32
	previous []byte
}

func processStartIdentity(stream string, pid int) string {
	prefix, _, ok := strings.Cut(stream, "/")
	if !ok {
		return ""
	}
	process, ticks, ok := strings.Cut(prefix, ":")
	if !ok {
		return ""
	}
	parsed, err := strconv.Atoi(process)
	if err != nil || parsed != pid || parsed <= 0 || uint64(parsed) > uint64(^uint32(0)) {
		return ""
	}
	value, err := strconv.ParseUint(ticks, 10, 64)
	if err != nil || value == 0 {
		return ""
	}
	return fmt.Sprintf("%d:%d", pid, value)
}
func newKernelScopeFile(directory string, snapshot kernelScopeSnapshot, ports map[int]bool) (*kernelScopeFile, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("kernel scope has no target provider")
	}
	scope := &kernelScopeFile{snapshot: snapshot}
	for port, selected := range ports {
		if selected {
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid scope port")
			}
			scope.ports = append(scope.ports, uint32(port))
		}
	}
	sort.Slice(scope.ports, func(i, j int) bool { return scope.ports[i] < scope.ports[j] })
	if len(scope.ports) == 0 {
		return nil, fmt.Errorf("kernel scope has no ports")
	}
	f, err := os.CreateTemp(directory, "kernel-scope-*.json")
	if err != nil {
		return nil, err
	}
	scope.path = f.Name()
	if err := f.Close(); err != nil {
		os.Remove(scope.path)
		return nil, err
	}
	if err := scope.update(); err != nil {
		os.Remove(scope.path)
		return nil, err
	}
	return scope, nil
}
func (s *kernelScopeFile) update() error {
	document := kernelScopeDocument{Version: 1, Ports: s.ports, PIDs: []kernelScopePID{}}
	selected := s.snapshot()
	if len(selected) > 4096 {
		return fmt.Errorf("kernel scope exceeds 4096 target processes")
	}
	for pid, id := range selected {
		identity := processStartIdentity(id+"/", pid)
		if identity == "" {
			return fmt.Errorf("invalid kernel scope process identity")
		}
		_, text, _ := strings.Cut(identity, ":")
		ticks, _ := strconv.ParseUint(text, 10, 64)
		document.PIDs = append(document.PIDs, kernelScopePID{uint32(pid), ticks})
	}
	sort.Slice(document.PIDs, func(i, j int) bool { return document.PIDs[i].PID < document.PIDs[j].PID })
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if len(data) > 256<<10 {
		return fmt.Errorf("kernel scope exceeds 256 KiB")
	}
	if bytes.Equal(data, s.previous) {
		return nil
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), "kernel-scope-write-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, s.path); err != nil {
		return err
	}
	s.previous = data
	return nil
}
func (s *kernelScopeFile) watch(ctx context.Context, failed func(error)) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				if err := s.update(); err != nil {
					failed(err)
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop); <-done }) }
}
