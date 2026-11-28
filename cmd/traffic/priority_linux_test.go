package main

import (
	"os"
	"runtime"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func threadNice(t *testing.T, tid int) int {
	t.Helper()
	raw, err := unix.Getpriority(unix.PRIO_PROCESS, tid)
	if err != nil {
		t.Fatal(err)
	}
	return 20 - raw
}

// Every thread ends at least as nice as requested, and a thread the operator
// already made nicer keeps its value.
func TestLowerCollectorPriorityCoversAllThreadsAndNeverRaises(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Keep this thread out of the pool: it exits with the goroutine.
		runtime.LockOSThread()
		self := unix.Gettid()
		if err := unix.Setpriority(unix.PRIO_PROCESS, self, 15); err != nil {
			t.Errorf("set test thread nice: %v", err)
			return
		}
		if err := lowerCollectorPriority(10); err != nil {
			t.Errorf("lowerCollectorPriority: %v", err)
			return
		}
		if got := threadNice(t, self); got != 15 {
			t.Errorf("nicer thread changed to %d", got)
		}
		entries, err := os.ReadDir("/proc/self/task")
		if err != nil {
			t.Error(err)
			return
		}
		for _, entry := range entries {
			tid, _ := strconv.Atoi(entry.Name())
			raw, err := unix.Getpriority(unix.PRIO_PROCESS, tid)
			if err != nil {
				continue // exited
			}
			if 20-raw < 10 {
				t.Errorf("thread %d nice %d", tid, 20-raw)
			}
		}
	}()
	<-done
}
