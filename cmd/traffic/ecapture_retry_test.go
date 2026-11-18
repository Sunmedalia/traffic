package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestECaptureRetriesAcrossRepeatedDisconnectsAndResetsAfterHealthyRun(t *testing.T) {
	now := time.Unix(100, 0)
	var delays []time.Duration
	attempt := 0
	superviseECapture(context.Background(), func(ready func()) error {
		attempt++
		ready()
		if attempt == 8 {
			now = now.Add(ecaptureHealthyRun)
		}
		if attempt == 10 {
			return nil
		}
		return io.ErrUnexpectedEOF
	}, func(string) {}, func(error, time.Duration) {}, func() time.Time { return now },
		func(_ context.Context, delay time.Duration) bool {
			delays = append(delays, delay)
			now = now.Add(delay)
			return true
		})
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 1, 2}
	for i := range want {
		want[i] *= time.Second
	}
	if attempt != 10 || !reflect.DeepEqual(delays, want) {
		t.Fatalf("attempts=%d delays=%v, want 10 attempts and %v", attempt, delays, want)
	}
}

func TestECapturePermanentFailureAndCancelledBackoff(t *testing.T) {
	for _, failure := range []error{fmt.Errorf("config: %w", errECaptureConfiguration), os.ErrPermission, os.ErrNotExist} {
		attempts := 0
		superviseECapture(context.Background(), func(func()) error {
			attempts++
			return failure
		}, func(string) {}, func(err error, delay time.Duration) {
			if err != failure || delay != 0 {
				t.Fatalf("permanent failure reported as retry: %v, %s", err, delay)
			}
		}, time.Now, func(context.Context, time.Duration) bool {
			t.Fatal("permanent failure entered backoff")
			return false
		})
		if attempts != 1 {
			t.Fatalf("permanent failure: %d attempts", attempts)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	superviseECapture(ctx, func(func()) error {
		attempts++
		return io.ErrUnexpectedEOF
	}, func(string) {}, func(error, time.Duration) { cancel() }, time.Now, waitECaptureRetry)
	if attempts != 1 {
		t.Fatalf("cancelled backoff started %d attempts", attempts)
	}
}
