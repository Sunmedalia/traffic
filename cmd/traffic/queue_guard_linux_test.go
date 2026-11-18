package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const testPrivateQueueOwner = "TRAFFIC_TEST_PRIVATE_QUEUE_OWNER"

func TestHelperPrivateQueueOwner(t *testing.T) {
	stage := os.Getenv(testPrivateQueueOwner)
	if stage == "" {
		return
	}
	socket, release, err := startPrivateQueueGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if stage == "bound" {
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
	}
	if err := json.NewEncoder(os.Stdout).Encode(socket); err != nil {
		t.Fatal(err)
	}
	// Keep the simulated collector alive until the test sends SIGKILL.
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}

func queueGuardTestTemp(t *testing.T) string {
	t.Helper()
	// Nested test names can exceed Linux's Unix socket pathname limit.
	dir, err := os.MkdirTemp("/tmp", "traffic-qtest-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestPrivateQueueGuardCleansUpAfterOwnerKill(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"before_bind", "bound"} {
		t.Run(stage, func(t *testing.T) {
			dir := queueGuardTestTemp(t)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			owner := exec.CommandContext(ctx, exe, "-test.run=^TestHelperPrivateQueueOwner$")
			owner.Env = append(os.Environ(), "TMPDIR="+dir, testPrivateQueueOwner+"="+stage)
			owner.Stderr = os.Stderr
			lifetime, err := owner.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer lifetime.Close()
			ready, err := owner.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = owner.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if owner.ProcessState == nil {
					_ = owner.Process.Kill()
					_ = owner.Wait()
				}
			}()
			var socket string
			if err = json.NewDecoder(ready).Decode(&socket); err != nil {
				t.Fatal(err)
			}
			if info, statErr := os.Lstat(socket); stage == "bound" {
				if statErr != nil || info.Mode()&os.ModeSocket == 0 {
					t.Fatalf("expected a bound socket, got %v, %v", info, statErr)
				}
			} else if !os.IsNotExist(statErr) {
				t.Fatalf("unexpected socket before bind: %v", statErr)
			}
			if err = owner.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = owner.Wait(); err == nil {
				t.Fatal("collector unexpectedly exited normally")
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				_, err = os.Lstat(filepath.Dir(socket))
				if os.IsNotExist(err) {
					break
				}
				if err != nil || time.Now().After(deadline) {
					t.Fatalf("private queue directory survived collector SIGKILL: %v", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestPrivateQueueGuardCleansUpOnBrokenReadinessPipe(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := queueGuardTestTemp(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	guard := exec.CommandContext(ctx, exe, privateQueueGuardArg)
	guard.Env = append(os.Environ(), "TMPDIR="+dir)
	guard.Stdout = writer
	if err := guard.Run(); err == nil || ctx.Err() != nil {
		t.Fatalf("guard did not handle closed readiness pipe: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("guard left directories after broken readiness pipe: %v, %v", entries, err)
	}
}
