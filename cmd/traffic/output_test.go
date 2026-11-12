package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAutomaticOutputDirectories(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 11, 11, 15, 4, 5, 0, time.FixedZone("CST", 8*60*60))
	first, err := prepareOutputDir("", root, "nginx", "test-host", now)
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(root, "test-host", "2026-11-11", "15-04-05-nginx")
	if first != expected {
		t.Fatalf("directory %s want %s", first, expected)
	}
	info, err := os.Stat(first)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("session permissions: %v %v", info, err)
	}
	const workers = 8
	paths := make(chan string, workers)
	failures := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			path, err := prepareOutputDir("", root, "nginx", "test-host", now)
			if err != nil {
				failures <- err
			} else {
				paths <- path
			}
		}()
	}
	wg.Wait()
	close(paths)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	unique := map[string]bool{first: true}
	for path := range paths {
		if unique[path] {
			t.Fatalf("session collision %s", path)
		}
		unique[path] = true
	}
	if len(unique) != workers+1 {
		t.Fatalf("reserved %d sessions", len(unique))
	}
	exact := filepath.Join(root, "custom-session")
	got, err := prepareOutputDir(exact, root, "incident", "test-host", now)
	if err != nil || got != exact {
		t.Fatalf("explicit output changed: %s %v", got, err)
	}
	for _, name := range []string{"../escape", "nested/name", "..", "", strings.Repeat("x", 81)} {
		if _, err := prepareOutputDir("", root, name, "test-host", now); err == nil {
			t.Fatalf("unsafe name accepted %q", name)
		}
	}
}

func writeImportFixture(t *testing.T, path string, broken bool) {
	t.Helper()
	// An empty little-endian Ethernet PCAP is sufficient to exercise CLI output.
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], 1)
	if broken {
		header = append(header, 1, 2, 3)
	}
	if err := os.WriteFile(path, header, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestImportCreatesOrganizedSession(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "source.pcap")
	dataDir := filepath.Join(root, "sessions")
	writeImportFixture(t, input, false)
	if err := run([]string{"import", input, "--data-dir", dataDir, "--name", "case-001"}); err != nil {
		t.Fatal(err)
	}
	indexes, err := filepath.Glob(filepath.Join(dataDir, "*", "*", "*", "index.sqlite"))
	if err != nil || len(indexes) != 1 {
		t.Fatalf("indexes %v %v", indexes, err)
	}
	dir := filepath.Dir(indexes[0])
	for _, name := range []string{"capture.lock", "status.json", "manifest.json", "packets"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	var manifest map[string]any
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["name"] != "case-001" || manifest["mode"] != "import" || manifest["layout_version"] != float64(2) {
		t.Fatalf("manifest %+v", manifest)
	}
	var status Stats
	raw, err = os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &status); err != nil || status.State != "complete" {
		t.Fatalf("status %+v %v", status, err)
	}
	// Explicit output stays compatible with verification and benchmark callers.
	exact := filepath.Join(root, "exact")
	if err = run([]string{"import", input, "--output", exact}); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(exact, "index.sqlite")); err != nil {
		t.Fatal(err)
	}
	failed := filepath.Join(root, "failed")
	writeImportFixture(t, input, true)
	if err = run([]string{"import", input, "--output", failed}); err == nil {
		t.Fatal("broken import succeeded")
	}
	raw, err = os.ReadFile(filepath.Join(failed, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &status); err != nil || status.State != "failed" || len(status.Errors) == 0 {
		t.Fatalf("failed session missing diagnosis %+v %v", status, err)
	}
}
func TestInvalidCaptureDoesNotCreateDirectories(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "unused")
	for _, args := range [][]string{
		{"capture", "--output", output, "--ports", "bad"},
		{"capture", "--output", output, "--interfaces", "../bad"},
		{"capture", "--output", output, "--name", "../bad"},
		{"capture", "--output", output, "--data-dir", root},
		{"import", filepath.Join(root, "missing.pcap"), "--output", output},
	} {
		if err := run(args); err == nil {
			t.Fatalf("invalid capture accepted %v", args)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("invalid capture left an output directory: %v", err)
		}
	}
}
