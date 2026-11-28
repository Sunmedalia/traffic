package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

var diskLimitMiB = 2048

var capturePorts = map[int]bool{80: true, 443: true}

var iisProbe, iisRuntime string
var iisPython = "python"

var opensslProbe, opensslProfile string

func parsePreloadUIDs(value string) ([]uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	seen := map[uint32]bool{}
	var uids []uint32
	for _, part := range strings.Split(value, ",") {
		number, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid preload sender UID %q", part)
		}
		uid := uint32(number)
		if !seen[uid] {
			seen[uid] = true
			uids = append(uids, uid)
		}
	}
	return uids, nil
}

var collectorMemoryMiB = 256

// pcapBufferMiB sizes the kernel capture ring of each libpcap interface. The
// libpcap default of 2 MiB holds only eight 256 KiB TPACKET_V3 blocks at the
// collector's snapshot length, about 16 ms of gigabit traffic, so short
// stalls overflowed it into unattributed kernel drops.
var pcapBufferMiB = 32

const (
	minPCAPBufferMiB = 2
	maxPCAPBufferMiB = 1024
)

var collectorCPUPercent = 50
var drainTimeout = 5 * time.Second

// stopTimeout bounds the whole shutdown after cancellation: packet sources,
// probe helpers and their own drain waits. Exceeding it records an explicit
// gap and finishes with drain_state=unverified instead of hanging.
var stopTimeout = 30 * time.Second

var networkNamespacePID int

// collectorNice lowers the collector's scheduling priority (and, on Linux
// schedulers that derive it from nice, its I/O priority) so the website wins
// when CPU or disk is contended. It matters most where the cgroup limits are
// unavailable and nothing else caps the collector. 0 keeps the inherited value.
var collectorNice = 10

const maxCollectorNice = 19

// minFreeMiB is the free space a session always leaves on its filesystem;
// 0 selects diskReserveBytes' automatic reserve.
var minFreeMiB = 0

// scaledDiskReserve is set for live capture, which runs on the website's own
// host. Import keeps the fixed floor.
var scaledDiskReserve = false

const (
	minDiskReserve = 512 << 20
	maxAutoReserve = 10 << 30
)

// diskReserveBytes scales the automatic capture reserve with the filesystem:
// 5% of its size, at least 512 MiB (the former fixed floor) and at most
// 10 GiB. A session on a shared system disk then stops well before the
// website's database or logs run out of space.
func diskReserveBytes(total uint64) uint64 {
	if minFreeMiB > 0 {
		return uint64(minFreeMiB) << 20
	}
	if !scaledDiskReserve {
		return minDiskReserve
	}
	return min(max(total/20, minDiskReserve), maxAutoReserve)
}
