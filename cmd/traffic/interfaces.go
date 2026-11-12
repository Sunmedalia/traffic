package main

import (
	"crypto/sha256"
	"fmt"
	"runtime"
	"strings"

	"github.com/google/gopacket/pcap"
)

func captureInterfaces(input string, offline bool) ([]string, error) {
	if offline {
		return []string{"offline"}, nil
	}
	if runtime.GOOS != "windows" {
		if input == "" {
			return []string{"any"}, nil
		}
		names := strings.Split(input, ",")
		for _, name := range names {
			if strings.TrimSpace(name) != name || name == "" || strings.ContainsAny(name, "/\\") {
				return nil, fmt.Errorf("invalid interface %q", name)
			}
		}
		return names, nil
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("Npcap interfaces: %w", err)
	}
	available := map[string]bool{}
	var defaults []string
	for _, device := range devices {
		available[device.Name] = true
		if device.Flags&0x30 != 0x20 && (len(device.Addresses) > 0 || strings.Contains(device.Name, "Loopback")) {
			defaults = append(defaults, device.Name)
		}
	}
	if input == "" {
		if len(defaults) == 0 {
			return nil, fmt.Errorf("no usable Npcap interfaces; run traffic doctor")
		}
		return defaults, nil
	}
	names := strings.Split(input, ",")
	seen := map[string]bool{}
	for _, name := range names {
		if !available[name] || seen[name] {
			return nil, fmt.Errorf("unknown or repeated Npcap interface %q; run traffic doctor", name)
		}
		seen[name] = true
	}
	return names, nil
}

func packetInterfaceName(name string) string {
	if !strings.ContainsAny(name, "/\\:") {
		return name
	}
	return fmt.Sprintf("adapter-%x", sha256.Sum256([]byte(name)))
}

func captureSnapshotLength() int32 {
	// Npcap loopback frames include a four-byte link header in addition to a
	// full-size IP packet. A 65535-byte snapshot silently loses the final bytes.
	if runtime.GOOS == "windows" {
		return 256 << 10
	}
	return 65535
}
