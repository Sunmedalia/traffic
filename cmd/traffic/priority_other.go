//go:build !linux && !windows

package main

import "golang.org/x/sys/unix"

// Outside Linux the nice value belongs to the process. Like Linux, this only
// ever lowers priority.
func lowerCollectorPriority(nice int) error {
	if nice == 0 {
		return nil
	}
	if current, err := unix.Getpriority(unix.PRIO_PROCESS, 0); err == nil && current >= nice {
		return nil
	}
	return unix.Setpriority(unix.PRIO_PROCESS, 0, nice)
}
