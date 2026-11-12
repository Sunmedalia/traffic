//go:build !windows

package session

import (
	"os"
	"syscall"
)

func PrivateUmask() { syscall.Umask(0077) }

func RestrictDirectory(path string) error { return os.Chmod(path, 0700) }

func LockFile(file *os.File, exclusive bool) error {
	mode := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		mode = syscall.LOCK_EX | syscall.LOCK_NB
	}
	return syscall.Flock(int(file.Fd()), mode)
}

func UnlockFile(file *os.File) error { return syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }

func FreeBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
