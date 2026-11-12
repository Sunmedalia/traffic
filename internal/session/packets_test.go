package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPacketFilesLayouts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case[1]?name")
	if err := os.MkdirAll(filepath.Join(root, "packets"), 0700); err != nil {
		t.Fatal(err)
	}
	expected := []string{filepath.Join(root, "packets-legacy-01.pcap"), filepath.Join(root, "packets", "any-01.pcap")}
	for _, name := range append(append([]string{}, expected...), filepath.Join(root, "manifest.json")) {
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := PacketFiles(root)
	if err != nil || len(files) != 2 {
		t.Fatalf("packet files %v %v", files, err)
	}
	for i := range expected {
		if files[i] != expected[i] {
			t.Fatalf("packet file %s want %s", files[i], expected[i])
		}
	}
	if err = os.RemoveAll(filepath.Join(root, "packets")); err != nil {
		t.Fatal(err)
	}
	files, err = PacketFiles(root)
	if err != nil || len(files) != 1 {
		t.Fatalf("legacy session %v %v", files, err)
	}
}
