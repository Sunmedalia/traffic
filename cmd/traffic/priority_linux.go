package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// lowerCollectorPriority renices every collector thread to at least nice.
// Linux keeps the nice value per thread, so setpriority(PRIO_PROCESS, 0)
// alone would change only the calling thread while Go runs work on many. New
// threads and helper processes (eCapture, the Java attach helper) inherit the
// value of the thread that creates them; a second pass covers threads started
// during the first. A thread already nicer than requested (the operator ran
// `nice -n 15 traffic ...`) is left alone: this only ever lowers priority.
// Without an explicit I/O priority the CFQ and BFQ schedulers derive one from
// nice, so the collector's own writeback also yields to the website.
func lowerCollectorPriority(nice int) error {
	if nice == 0 {
		return nil
	}
	for pass := 0; pass < 2; pass++ {
		entries, err := os.ReadDir("/proc/self/task")
		if err != nil {
			return err
		}
		for _, entry := range entries {
			tid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			// The raw syscall returns 20 - nice so that it is never negative.
			raw, err := unix.Getpriority(unix.PRIO_PROCESS, tid)
			if err == nil && 20-raw >= nice {
				continue
			}
			if err == nil {
				err = unix.Setpriority(unix.PRIO_PROCESS, tid, nice)
			}
			if err != nil && !errors.Is(err, unix.ESRCH) { // ESRCH: thread exited
				return fmt.Errorf("thread %d: %w", tid, err)
			}
		}
	}
	return nil
}
