package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSessionLocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.lock")
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := LockFile(writer, true); err != nil {
		t.Fatal(err)
	}
	if err := LockFile(reader, false); err == nil {
		t.Fatal("export lock must fail while collector owns the session")
	}
	if err := UnlockFile(writer); err != nil {
		t.Fatal(err)
	}
	if err := LockFile(reader, false); err != nil {
		t.Fatal(err)
	}
	defer UnlockFile(reader)
	if err := LockFile(writer, true); err == nil {
		t.Fatal("collector lock must fail while exporter owns the session")
	}
}
