package main

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestShutdownPropagatesPlaintextFailure(t *testing.T) {
	s := &Store{iisAttached: true}
	if err := finishCaptureState(s, false, true, false); err == nil {
		t.Fatal("required plaintext failure was lost")
	}
	if s.stats.State != "failed" || s.stats.StopReason != "fatal_error" {
		t.Fatalf("misleading success: %+v", s.stats)
	}
}

func TestShutdownSharedDeadlineAndLateCloseError(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	started := time.Now()
	exceeded, err := shutdownWithin(func() {}, func() error { <-release; return errors.New("late close") }, 20*time.Millisecond)
	if !exceeded || err != nil {
		t.Fatalf("blocked recorder: exceeded=%v err=%v", exceeded, err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("close escaped shutdown budget")
	}
	// The timeout result must not share mutable state with the late close.
	s := &Store{}
	s.fail(errors.New("shutdown timeout"))
	if finishCaptureState(s, true, false, exceeded) == nil || s.stats.State != "failed" || s.stats.DrainState != "unverified" || s.stats.StopReason != "stop_budget_exceeded" {
		t.Fatalf("timeout reported as success: %+v", s.stats)
	}
	failure := errors.New("sync failed")
	exceeded, err = shutdownWithin(func() {}, func() error { return failure }, time.Second)
	if exceeded || !errors.Is(err, failure) {
		t.Fatalf("close failure lost: %v %v", exceeded, err)
	}
}

func TestShutdownDoesNotWaitAgainForHungWorker(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	closed := make(chan struct{})
	exceeded, err := shutdownWithin(func() { <-release }, func() error { close(closed); return nil }, 20*time.Millisecond)
	if !exceeded || err != nil {
		t.Fatal("hung worker accepted", exceeded, err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("recorder close was not initiated")
	}
}

func TestShutdownSnapshotDetachedFromLiveWorkers(t *testing.T) {
	s := &Store{}
	s.stats.GapCounts = map[string]uint64{"test": 1}
	s.stats.Errors = []string{"before"}
	snapshot := snapshotStats(s)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			s.mu.Lock()
			s.stats.GapCounts["test"]++
			s.stats.Errors[0] = "after"
			s.mu.Unlock()
		}
	}()
	for i := 0; i < 100; i++ {
		if _, err := json.Marshal(snapshot); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if snapshot.GapCounts["test"] != 1 || snapshot.Errors[0] != "before" {
		t.Fatal("snapshot aliases live status")
	}
}
