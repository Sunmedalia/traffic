package main

import "os"

// evidenceStreamWindow is how much evidence is written between page-cache
// release steps. One window stays in flight while the previous one is released.
const evidenceStreamWindow = 8 << 20

// evidenceFile is an append-only evidence file (PCAP segment or raw probe
// stream) that the collector never reads back. On Linux, page cache for these
// writes is charged to the collector's memory cgroup; left alone it fills the
// --collector-memory-mib budget after a few hundred MiB of evidence, and the
// kernel then throttles the collector's own allocations while dirty pages are
// written back, which sheds or stops capture. evidenceFile starts writeback
// early and releases windows that are already on disk, so the cache it holds
// stays near two windows regardless of session length.
type evidenceFile struct {
	*os.File
	written  int64
	started  int64
	released int64
	disabled bool
}

func newEvidenceFile(f *os.File) *evidenceFile { return &evidenceFile{File: f} }

func (f *evidenceFile) Write(p []byte) (int, error) {
	n, err := f.File.Write(p)
	f.written += int64(n)
	if err == nil && !f.disabled && f.written-f.started >= evidenceStreamWindow {
		err = f.releaseWritten(false)
	}
	return n, err
}

// Sync makes the file durable, then releases everything written so far.
func (f *evidenceFile) Sync() error {
	if err := f.File.Sync(); err != nil {
		return err
	}
	if f.disabled {
		return nil
	}
	return f.releaseWritten(true)
}
