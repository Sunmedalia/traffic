package main

import (
	"os/exec"
	"runtime"
	"syscall"
)

// Linux binds Pdeathsig to the creating thread. Keep that thread alive until
// the direct child has been reaped, including during ordinary probe teardown.
func bindProbeParent(cmd *exec.Cmd) func() {
	runtime.LockOSThread()
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return runtime.UnlockOSThread
}
