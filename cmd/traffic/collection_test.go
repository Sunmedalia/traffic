package main

import (
	"bytes"
	"encoding/json"
	"github.com/Sunmedalia/traffic/internal/session"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectorPreservesRawBytesWithoutIndex(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	r := newRecorder(s)
	defer r.close()
	target := session.Target{PID: 17, ID: "17:original", Service: "nginx", Ports: []int{443}}
	data := bytes.Repeat([]byte("unparsed \x00 bytes union select 1"), 20000)
	if err = r.record("test-generation", "openssl", target, session.RawEvent{Type: "data", Connection: "c", Direction: "read", Data: data, Local: "127.0.0.1:443", Client: "192.0.2.1:1234"}); err != nil {
		t.Fatal(err)
	}
	if err = r.close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "tls", "stream.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 2 {
		t.Fatal("unexpected records", len(lines))
	}
	var metadata, event session.RawEvent
	json.Unmarshal(lines[0], &metadata)
	json.Unmarshal(lines[1], &event)
	if metadata.Target == nil || metadata.Target.ID != target.ID || !bytes.Equal(event.Data, data) {
		t.Fatal("raw payload or target identity changed")
	}
	if _, err = os.Stat(filepath.Join(s.dir, "index.sqlite")); !os.IsNotExist(err) {
		t.Fatal("collector created an index")
	}
	for _, args := range [][]string{{"rules", "check", "x.yaml"}, {"capture", "--rules", "x.yaml"}, {"capture", "--request-limit", "100"}, {"capture", "--alert-webhook", "https://example.invalid"}} {
		if run(args) == nil {
			t.Fatalf("collector accepted analysis option %v", args)
		}
	}
}
