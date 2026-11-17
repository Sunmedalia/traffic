package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeInitializationPreservesData(t *testing.T) {
	root := t.TempDir()
	if err := initRuntimeAt(root); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(root, "sessions", "existing")
	if err := os.WriteFile(saved, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initRuntimeAt(root); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(saved); err != nil || string(data) != "keep" {
		t.Fatalf("existing data: %q, %v", data, err)
	}
	for _, name := range []string{"sessions", "exports"} {
		if info, err := os.Stat(filepath.Join(root, name)); err != nil || !info.IsDir() {
			t.Fatalf("missing %s", name)
		}
	}
}

func TestRuntimeInitializationReportsBlockedPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sessions"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := initRuntimeAt(root); err == nil {
		t.Fatal("expected blocked directory error")
	}
}
