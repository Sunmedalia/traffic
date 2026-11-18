package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

var errECaptureConfiguration = errors.New("invalid eCapture configuration")

const (
	ecaptureInitialRetry = time.Second
	ecaptureMaxRetry     = 30 * time.Second
	ecaptureHealthyRun   = 30 * time.Second
)

func permanentECaptureFailure(err error) bool {
	return errors.Is(err, errECaptureConfiguration) || errors.Is(err, os.ErrPermission) ||
		errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound) || errors.Is(err, syscall.ENOEXEC)
}

// superviseECapture is scoped to one selected probe group. Discovery cancels
// it when the target disappears. A run must be cleaned up before retrying.
func superviseECapture(ctx context.Context, run func(ready func()) error, state func(string),
	reportFailure func(error, time.Duration), now func() time.Time, wait func(context.Context, time.Duration) bool) {
	backoff := ecaptureInitialRetry
	for ctx.Err() == nil {
		state("starting")
		var attachedAt time.Time
		err := run(func() {
			attachedAt = now()
			state("attached")
		})
		if ctx.Err() != nil || err == nil {
			return
		}
		state("unavailable")
		if permanentECaptureFailure(err) {
			reportFailure(err, 0)
			return
		}
		if !attachedAt.IsZero() && now().Sub(attachedAt) >= ecaptureHealthyRun {
			backoff = ecaptureInitialRetry
		}
		reportFailure(err, backoff)
		if !wait(ctx, backoff) {
			return
		}
		backoff = min(ecaptureMaxRetry, 2*backoff)
	}
}

func waitECaptureRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
