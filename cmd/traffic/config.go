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
var collectorCPUPercent = 50
var drainTimeout = 5 * time.Second

// stopTimeout bounds the whole shutdown after cancellation: packet sources,
// probe helpers and their own drain waits. Exceeding it records an explicit
// gap and finishes with drain_state=unverified instead of hanging.
var stopTimeout = 30 * time.Second

var networkNamespacePID int
