package main

import (
	"os"
	"strings"
	"testing"
)

func TestMemoryBackedSessionIsRefused(t *testing.T) {
	shm, err := os.MkdirTemp("/dev/shm", "traffic-memfs-")
	if err != nil {
		t.Skip("no /dev/shm:", err)
	}
	defer os.RemoveAll(shm)
	if _, ok := memoryBackedFilesystem(shm); !ok {
		t.Skip("/dev/shm is not tmpfs here")
	}
	oldDisk, oldMemory := diskLimitMiB, collectorMemoryMiB
	defer func() { diskLimitMiB, collectorMemoryMiB = oldDisk, oldMemory }()
	collectorMemoryMiB = 256
	diskLimitMiB = 2048
	if err := checkMemoryBackedSession(shm); err == nil || !strings.Contains(err.Error(), "tmpfs") || !strings.Contains(err.Error(), "128") {
		t.Fatal("tmpfs session above half the memory budget accepted", err)
	}
	diskLimitMiB = 128
	if err := checkMemoryBackedSession(shm); err != nil {
		t.Fatal("small tmpfs session refused", err)
	}
}

func TestDiskSessionIsNotMemoryBacked(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if kind, ok := memoryBackedFilesystem(wd); ok {
		t.Skip("working directory is on", kind)
	}
	oldDisk := diskLimitMiB
	defer func() { diskLimitMiB = oldDisk }()
	diskLimitMiB = 1 << 20
	if err := checkMemoryBackedSession(wd); err != nil {
		t.Fatal(err)
	}
}
