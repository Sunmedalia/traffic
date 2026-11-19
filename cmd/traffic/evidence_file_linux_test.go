package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// residentPages counts cached pages of path within [offset, offset+length).
func residentPages(t *testing.T, path string, offset, length int64) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	mapped, err := unix.Mmap(int(f.Fd()), offset, int(length), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mapped)
	page := os.Getpagesize()
	vec := make([]byte, (len(mapped)+page-1)/page)
	if _, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapped[0])), uintptr(len(mapped)), uintptr(unsafe.Pointer(&vec[0]))); errno != 0 {
		t.Fatal(errno)
	}
	resident := 0
	for _, v := range vec {
		resident += int(v & 1)
	}
	return resident
}

func TestEvidenceFileReleasesWrittenCache(t *testing.T) {
	dir := t.TempDir()
	if wd, err := os.Getwd(); err == nil {
		// Prefer a disk-backed directory: tmpfs pages are the storage itself.
		if probe, err := os.MkdirTemp(wd, ".evidence-file-test-*"); err == nil {
			dir = probe
			t.Cleanup(func() { os.RemoveAll(probe) })
		}
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "stream.jsonl")
	raw, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f := newEvidenceFile(raw)
	chunk := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	hash := sha256.New()
	const total = 40 << 20
	for written := 0; written < total; written += len(chunk) {
		chunk[0] = byte(written >> 16)
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
		hash.Write(chunk)
	}
	if f.disabled {
		t.Skip("filesystem does not support writeback hints")
	}
	if f.released < total-3*evidenceStreamWindow {
		t.Fatalf("only %d of %d bytes released before sync", f.released, total)
	}
	if fs.Type != unix.TMPFS_MAGIC {
		if resident := residentPages(t, path, 0, f.released); resident > int(f.released)/os.Getpagesize()/10 {
			t.Fatalf("%d pages of released evidence still cached", resident)
		}
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if f.released != total {
		t.Fatalf("sync released %d of %d bytes", f.released, total)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sha256.Sum256(data), hash.Sum(nil); len(data) != total || !bytes.Equal(got[:], want) {
		t.Fatal("evidence content changed by cache release")
	}
}
