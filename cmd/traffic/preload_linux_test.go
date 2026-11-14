package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPreloadSocketRefusesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if connection, err := openPreloadSocket(path); err == nil {
		connection.Close()
		t.Fatal("overwrote existing path")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "preserve" {
		t.Fatal("existing file changed")
	}
	if connection, err := openPreloadSocket("relative.sock"); err == nil {
		connection.Close()
		t.Fatal("accepted relative socket")
	}
}

func TestPreloadCredentialAndProcessIdentity(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	store, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
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
	go func() { done <- capturePreload(ctx, store, newHTTP(store), path) }()
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
	for {
		var data []byte
		if err := store.db.QueryRow("SELECT data FROM requests").Scan(&data); err == nil && strings.Contains(string(data), `"status":200`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no completed request")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM requests").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("untrusted event accepted: %d", count)
	}
	var raw []byte
	if err := store.db.QueryRow("SELECT data FROM requests").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var record Transaction
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.URL != "/valid" || record.Backend != "openssl-preload" || record.Status != 200 || len(record.Alerts) != 1 {
		t.Fatalf("bad capture %+v", record)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("socket leaked")
	}
}
