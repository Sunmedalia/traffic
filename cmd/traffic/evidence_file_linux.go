package main

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// releaseWritten starts asynchronous writeback for data written since the last
// step and drops windows that are at least one window old (all data when
// synced). Waiting only on the older window keeps the writer from blocking on
// the device in the common case while bounding dirty and cached evidence.
func (f *evidenceFile) releaseWritten(synced bool) error {
	fd := int(f.Fd())
	if f.written > f.started {
		if err := unix.SyncFileRange(fd, f.started, f.written-f.started, unix.SYNC_FILE_RANGE_WRITE); err != nil {
			return f.releaseError(err)
		}
		f.started = f.written
	}
	target := f.started - evidenceStreamWindow
	if synced {
		target = f.written
	}
	if target <= f.released {
		return nil
	}
	if !synced {
		flags := unix.SYNC_FILE_RANGE_WAIT_BEFORE | unix.SYNC_FILE_RANGE_WRITE | unix.SYNC_FILE_RANGE_WAIT_AFTER
		if err := unix.SyncFileRange(fd, f.released, target-f.released, flags); err != nil {
			return f.releaseError(err)
		}
	}
	// DONTNEED drops only whole clean pages; a partial tail page stays cached.
	if err := unix.Fadvise(fd, f.released, target-f.released, unix.FADV_DONTNEED); err != nil {
		return f.releaseError(err)
	}
	f.released = target
	return nil
}

// releaseError reports device failures as write failures so they reach the
// evidence error classification; a filesystem without support for these hints
// only loses the cache release.
func (f *evidenceFile) releaseError(err error) error {
	if errors.Is(err, syscall.EIO) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return err
	}
	f.disabled = true
	return nil
}
