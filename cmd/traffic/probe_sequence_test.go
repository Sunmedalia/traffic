package main

import "testing"

func TestProbeSequenceGapsAndResets(t *testing.T) {
	var sequence probeSequence
	for _, step := range []struct {
		value, missing uint64
		reset          bool
	}{
		{0, 0, false}, {1, 0, false}, {2, 0, false}, {5, 2, false},
		{5, 0, true}, {3, 0, true}, {4, 0, false}, {0, 0, true}, {0, 0, false}, {1, 0, false},
	} {
		missing, reset := sequence.observe(step.value)
		if missing != step.missing || reset != step.reset {
			t.Fatalf("sequence %d: got %d/%v want %d/%v", step.value, missing, reset, step.missing, step.reset)
		}
	}
	var startup probeSequence
	if missing, reset := startup.observe(9); missing != 8 || reset {
		t.Fatal("startup sequence gap not counted", missing, reset)
	}
	var boundary probeSequence
	boundary.last = ^uint64(0)
	if missing, reset := boundary.observe(1); missing != 0 || !reset {
		t.Fatal("sequence wrap was mistaken for a contiguous stream", missing, reset)
	}
}
