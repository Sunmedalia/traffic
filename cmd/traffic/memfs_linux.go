package main

import "golang.org/x/sys/unix"

// memoryBackedFilesystem names the filesystem holding path when its files live
// in RAM. Their pages are shmem: they count toward the collector's memory
// cgroup and cannot be reclaimed or written back.
func memoryBackedFilesystem(path string) (string, bool) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return "", false
	}
	switch fs.Type {
	case unix.TMPFS_MAGIC:
		return "tmpfs", true
	case unix.RAMFS_MAGIC:
		return "ramfs", true
	}
	return "", false
}
