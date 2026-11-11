package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// limitResources contains this process and its future children in a cgroup.
// Moving only this PID leaves the parent SSH session and website outside it.
func limitResources() (func(), error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	var parent string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			parent = filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::"))
		}
	}
	if parent == "" {
		return nil, fmt.Errorf("cgroup v2 unavailable")
	}
	group := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("traffic-%d", os.Getpid()))
	if err = os.Mkdir(group, 0700); err != nil {
		return nil, err
	}
	cleanup := func() {
		if err := os.WriteFile(filepath.Join(parent, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.WriteFile("/sys/fs/cgroup/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0600)
		}
		os.Remove(group)
	}
	for name, value := range map[string]string{"memory.max": "268435456", "memory.swap.max": "0", "cpu.max": "50000 100000", "pids.max": "256"} {
		if err = os.WriteFile(filepath.Join(group, name), []byte(value), 0600); err != nil {
			os.Remove(group)
			return nil, err
		}
	}
	if err = os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Remove(group)
		return nil, err
	}
	return cleanup, nil
}
