package session

import (
	"os"
	"path/filepath"
	"strings"
)

// PacketFiles supports both the original flat layout and organized sessions.
func PacketFiles(dir string) ([]string, error) {
	var result []string
	for _, folder := range []string{dir, filepath.Join(dir, "packets")} {
		entries, err := os.ReadDir(folder)
		if os.IsNotExist(err) && folder != dir {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".pcap") && (folder != dir || strings.HasPrefix(entry.Name(), "packets-")) {
				result = append(result, filepath.Join(folder, entry.Name()))
			}
		}
	}
	return result, nil
}

// PacketSegmentGroup identifies the capture interface that owns a segment.
func PacketSegmentGroup(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), ".pcap")
	if index := strings.LastIndexByte(base, '-'); index >= 0 {
		base = base[:index]
	}
	return filepath.Join(filepath.Dir(path), base)
}
