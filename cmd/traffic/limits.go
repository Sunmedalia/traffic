//go:build !windows

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
		cleanup, err := limitResourcesV1(data)
		if err == nil {
			resourceControlVersion = "cgroup-v1"
		}
		return cleanup, err
	}
	root := "/sys/fs/cgroup"
	origin := filepath.Clean(parent)
	var lastErr error
	for base := origin; base == root || strings.HasPrefix(base, root+string(os.PathSeparator)); base = filepath.Dir(base) {
		group := filepath.Join(base, fmt.Sprintf("traffic-%d", os.Getpid()))
		if err := os.Mkdir(group, 0700); err != nil {
			lastErr = err
			if base == root {
				break
			}
			continue
		}
		configured := true
		for name, value := range map[string]string{"memory.max": strconv.FormatInt(int64(collectorMemoryMiB)<<20, 10), "memory.swap.max": "0", "cpu.max": fmt.Sprintf("%d 100000", collectorCPUPercent*1000), "pids.max": "256"} {
			if err := os.WriteFile(filepath.Join(group, name), []byte(value), 0600); err != nil {
				lastErr = err
				configured = false
				break
			}
		}
		if configured {
			if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
				lastErr = err
				configured = false
			}
		}
		if configured {
			cleanup := func() {
				if err := os.WriteFile(filepath.Join(origin, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
					_ = os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600)
				}
				_ = os.Remove(group)
			}
			return cleanup, nil
		}
		_ = os.Remove(group)
		if base == root {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("current cgroup is outside the available cgroup v2 mount")
	}
	return nil, fmt.Errorf("no existing ancestor delegates the required controllers: %w", lastErr)
}

var resourceControlVersion = "cgroup-v2"

func resourceLimitDescription() string {
	return fmt.Sprintf("%s: %dMiB, %d%% of one CPU", resourceControlVersion, collectorMemoryMiB, collectorCPUPercent)
}
