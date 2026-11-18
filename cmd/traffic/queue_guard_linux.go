package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

const (
	privateQueueGuardArg = "_traffic-queue-guard"
	privateQueueSocket   = "q.sock"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != privateQueueGuardArg {
		return
	}
	// The collector may die before reading readiness. A broken stdout
	// pipe must return EPIPE so the helper can still clean up.
	signal.Ignore(syscall.SIGPIPE)
	if err := guardPrivateQueue(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "private queue guard:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func startPrivateQueueGuard() (string, func() error, error) {
	// Use the running binary even if an installation update replaces it.
	cmd := exec.Command("/proc/self/exe", privateQueueGuardArg)
	cmd.Args[0] = "traffic-queue-guard"
	cmd.Stderr = os.Stderr
	// Keep the helper outside the collector's terminal process group.
	// It must survive the collector and its probe to remove the socket.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	owner, err := cmd.StdinPipe()
	if err != nil {
		return "", nil, err
	}
	ready, err := cmd.StdoutPipe()
	if err != nil {
		_ = owner.Close()
		return "", nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = ready.Close()
		_ = owner.Close()
		return "", nil, err
	}
	release := func() error {
		_ = owner.Close()
		return cmd.Wait()
	}
	var socket string
	err = json.NewDecoder(io.LimitReader(ready, 4096)).Decode(&socket)
	_ = ready.Close()
	if err != nil {
		return "", nil, errors.Join(fmt.Errorf("queue guard readiness: %w", err), release())
	}
	return socket, release, nil
}

func guardPrivateQueue(owner io.Reader, ready io.Writer) (err error) {
	// The guard creates the path before reporting it, so no directory is
	// created during a window without a process responsible for cleanup.
	temp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(temp, "traffic-eq-")
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.Join(err, os.Remove(dir))
	}
	defer root.Close()
	defer func() { err = errors.Join(err, removePrivateQueue(dir, root)) }()
	socket := filepath.Join(dir, privateQueueSocket)
	if len(socket) >= 104 {
		return fmt.Errorf("private queue socket path too long: %s", socket)
	}
	if err := json.NewEncoder(ready).Encode(socket); err != nil {
		return err
	}
	// The write end is held only by the collector and closed by the
	// kernel even on SIGKILL. Probe children do not inherit it.
	_, err = io.Copy(io.Discard, owner)
	return err
}

func removePrivateQueue(dir string, root *os.Root) error {
	owned, err := root.Stat(".")
	if err != nil {
		return err
	}
	stat, ok := owned.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || owned.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private queue directory ownership or permissions changed: %s", dir)
	}
	// A probe can race the first unlink with its initial bind. Once the
	// directory is removed the probe cannot create another socket there.
	for range 2 {
		current, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !os.SameFile(owned, current) {
			return fmt.Errorf("private queue directory was replaced: %s", dir)
		}
		if err := root.Remove(privateQueueSocket); err != nil && !os.IsNotExist(err) {
			return err
		}
		err = os.Remove(dir)
		if !errors.Is(err, syscall.ENOTEMPTY) {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
	}
	return fmt.Errorf("private queue directory still contains entries: %s", dir)
}
