//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Only create child groups under this process's current controller groups.
// Never move the website, parent shell or unrelated services.
func limitResourcesV1(data []byte) (func(), error) {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, err
	}
	locations := map[string]string{}
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "cgroup" {
			continue
		}
		for _, controller := range strings.Split(fields[3], ",") {
			if controller == "cpu" || controller == "memory" {
				locations[controller] = fields[1]
			}
		}
	}
	parents := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		for _, controller := range strings.Split(fields[1], ",") {
			if mount := locations[controller]; mount != "" {
				parents[controller] = filepath.Join(mount, strings.TrimPrefix(fields[2], "/"))
			}
		}
	}
	if parents["cpu"] == "" || parents["memory"] == "" {
		return nil, fmt.Errorf("cgroup v1 CPU/memory controllers unavailable")
	}
	pid := []byte(strconv.Itoa(os.Getpid()))
	var created []string
	cleanup := func() {
		for _, controller := range []string{"cpu", "memory"} {
			_ = os.WriteFile(filepath.Join(parents[controller], "cgroup.procs"), pid, 0600)
		}
		for _, group := range created {
			_ = os.Remove(group)
		}
	}
	for _, controller := range []string{"memory", "cpu"} {
		group := filepath.Join(parents[controller], fmt.Sprintf("traffic-%d", os.Getpid()))
		if err := os.Mkdir(group, 0700); err != nil {
			cleanup()
			return nil, err
		}
		created = append(created, group)
		limits := map[string]string{"cpu.cfs_period_us": "100000", "cpu.cfs_quota_us": strconv.Itoa(collectorCPUPercent * 1000)}
		if controller == "memory" {
			limits = map[string]string{"memory.limit_in_bytes": strconv.FormatInt(int64(collectorMemoryMiB)<<20, 10)}
		}
		for file, value := range limits {
			if err := os.WriteFile(filepath.Join(group, file), []byte(value), 0600); err != nil {
				cleanup()
				return nil, err
			}
		}
		if controller == "memory" {
			if _, err := os.Stat(filepath.Join(group, "memory.memsw.limit_in_bytes")); err == nil {
				if err := os.WriteFile(filepath.Join(group, "memory.memsw.limit_in_bytes"), []byte(strconv.FormatInt(int64(collectorMemoryMiB)<<20, 10)), 0600); err != nil {
					cleanup()
					return nil, err
				}
			}
		}
		if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), pid, 0600); err != nil {
			cleanup()
			return nil, err
		}
	}
	return cleanup, nil
}
