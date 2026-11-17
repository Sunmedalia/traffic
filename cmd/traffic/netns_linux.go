package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// Setns is thread-local. Always use a dedicated locked thread and restore it
// before publishing results; a failed restoration never returns that thread to Go.
func inCaptureNamespace(fn func() error) error {
	if networkNamespacePID == 0 {
		return fn()
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, err := os.Open("/proc/self/task/" + strconv.Itoa(unix.Gettid()) + "/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			result <- err
			return
		}
		defer original.Close()
		target, err := os.Open("/proc/" + strconv.Itoa(networkNamespacePID) + "/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			result <- err
			return
		}
		defer target.Close()
		if err = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enter network namespace: %w", err)
			return
		}
		err = fn()
		if restore := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restore != nil {
			result <- fmt.Errorf("restore capture thread namespace: %w", restore)
			return
		}
		runtime.UnlockOSThread()
		result <- err
	}()
	return <-result
}
