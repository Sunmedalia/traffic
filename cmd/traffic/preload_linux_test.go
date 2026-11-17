package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/Sunmedalia/traffic/internal/session"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPreloadSocketRefusesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if connection, err := openPreloadSocket(path, nil); err == nil {
		connection.Close()
		t.Fatal("overwrote existing path")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "preserve" {
		t.Fatal("existing file changed")
	}
	if connection, err := openPreloadSocket("relative.sock", nil); err == nil {
		connection.Close()
		t.Fatal("accepted relative socket")
	}
}

func TestPreloadCredentialAndProcessIdentity(t *testing.T) {
	store, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	recorder := newRecorder(store)
	defer recorder.close()
	// Unix socket names are limited to 108 bytes, including the terminating NUL.
	directory, err := os.MkdirTemp("/tmp", "traffic-preload-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "events.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- capturePreload(ctx, store, recorder, path, nil) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket did not open")
		}
		time.Sleep(time.Millisecond)
	}
	sender, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	identity, err := processIdentity("/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	connection := strconv.Itoa(os.Getpid()) + "-test"
	send := func(id, kind, direction, payload string) {
		t.Helper()
		event := struct {
			opensslEvent
			ProcessID string `json:"process_id"`
		}{opensslEvent: opensslEvent{Type: kind, Protocol: "traffic-openssl-v1", Connection: connection, Direction: direction, Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Data: []byte(payload)}, ProcessID: id}
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sender.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	send("forged", "data", "read", "GET /forged HTTP/1.1\r\nHost: test\r\n\r\n")
	send(identity, "data", "read", "GET /valid HTTP/1.1\r\nHost: test\r\n\r\n")
	send(identity, "data", "write", "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nroot:x:0:0:")
	send(identity, "close", "", "")
	deadline = time.Now().Add(3 * time.Second)
	rawPath := filepath.Join(store.dir, "tls", "stream.jsonl")
	for {
		data, _ := os.ReadFile(rawPath)
		if bytes.Contains(data, []byte(`"type":"close"`)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no recorded close event")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := recorder.close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	var payloads [][]byte
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var e session.RawEvent
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if e.Type == "data" {
			payloads = append(payloads, e.Data)
		}
	}
	if len(payloads) != 2 || !bytes.Contains(payloads[0], []byte("/valid")) || bytes.Contains(raw, []byte("forged")) {
		t.Fatal("untrusted event accepted or raw data changed")
	}
	if _, err := os.Stat(filepath.Join(store.dir, "index.sqlite")); !os.IsNotExist(err) {
		t.Fatal("collector created index")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("socket leaked")
	}
}

func TestPreloadSocketCreatesMissingDirectory(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "traffic-sock-dir-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "run", "traffic", "events.sock")
	connection, err := openPreloadSocket(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode %o", info.Mode().Perm())
	}
	if directory, err := os.Stat(filepath.Dir(path)); err != nil || directory.Mode().Perm() != 0755 {
		t.Fatalf("socket directory mode %v %v", directory, err)
	}
}

func TestPreloadAllowUIDDoesNotChangeExistingParentMode(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "traffic-preload-mode-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	socket, err := openPreloadSocket(filepath.Join(directory, "events.sock"), []uint32{uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("private parent directory was exposed: %o", info.Mode().Perm())
	}
}
