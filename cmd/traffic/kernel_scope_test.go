package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestKernelScopeFileTracksPIDReuseAndRemoval(t *testing.T) {
	selected := map[int]string{42: "42:100", 43: "43:200"}
	scope, err := newKernelScopeFile(t.TempDir(), func() map[int]string { return selected }, map[int]bool{443: true, 80: true})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(scope.path)
	read := func() kernelScopeDocument {
		data, err := os.ReadFile(scope.path)
		if err != nil {
			t.Fatal(err)
		}
		var cfg kernelScopeDocument
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfg := read()
	if len(cfg.PIDs) != 2 || cfg.PIDs[0].PID != 42 || cfg.Ports[0] != 80 {
		t.Fatal("scope snapshot is not stable and sorted", cfg)
	}
	original, err := os.Stat(scope.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.update(); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := os.Stat(scope.path)
	if !os.SameFile(original, unchanged) {
		t.Fatal("unchanged scope needlessly rewrote file")
	}
	selected = map[int]string{42: "42:300"}
	if err := scope.update(); err != nil {
		t.Fatal(err)
	}
	cfg = read()
	if len(cfg.PIDs) != 1 || cfg.PIDs[0].StartTicks != 300 {
		t.Fatal("retired process identity remained", cfg)
	}
	changed, _ := os.Stat(scope.path)
	if os.SameFile(original, changed) {
		t.Fatal("scope update did not atomically replace snapshot")
	}
	selected = map[int]string{}
	if err := scope.update(); err != nil {
		t.Fatal(err)
	}
	if cfg = read(); len(cfg.PIDs) != 0 {
		t.Fatal("empty scope must revoke every PID", cfg)
	}
	if st, _ := os.Stat(scope.path); st.Mode().Perm()&0077 != 0 {
		t.Fatal("scope snapshot is not private", st.Mode())
	}
}
func TestKernelScopeRejectsInvalidIdentitiesAndPreservesSnapshot(t *testing.T) {
	selected := map[int]string{42: "42:1"}
	scope, err := newKernelScopeFile(t.TempDir(), func() map[int]string { return selected }, map[int]bool{443: true})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(scope.path)
	before, _ := os.ReadFile(scope.path)
	selected = map[int]string{42: "43:1"}
	if err := scope.update(); err == nil {
		t.Fatal("mismatched process identity accepted")
	}
	after, _ := os.ReadFile(scope.path)
	if string(before) != string(after) {
		t.Fatal("failed update destroyed last complete snapshot")
	}
	for _, stream := range []string{"42_inode_1", "43:1/connection", "42:0/connection", "42:bad/connection", "42:1"} {
		if processStartIdentity(stream, 42) != "" {
			t.Fatal("invalid wire identity accepted", stream)
		}
	}
	if got := processStartIdentity("42:1234/42_inode_987", 42); got != "42:1234" {
		t.Fatal(got)
	}
}
