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

func TestPreloadStopBlocksNewEventsDrainsAcceptedAndKeepsUnverified(t *testing.T) {
	oldPorts, oldDrain := capturePorts, drainTimeout
	capturePorts = map[int]bool{443: true}
	drainTimeout = 2 * time.Second
	defer func() {
		capturePorts, drainTimeout = oldPorts, oldDrain
	}()

	store, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	recorder := newRecorder(store)
	directory, err := os.MkdirTemp("/tmp", "traffic-preload-drain-")
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
	connKey := strconv.Itoa(os.Getpid()) + "-drain"
	encodeEvent := func(seq uint64, reqID string) []byte {
		event := struct {
			opensslEvent
			ProcessID string `json:"process_id"`
		}{
			opensslEvent: opensslEvent{
				Sequence:   seq,
				Type:       "data",
				Protocol:   "traffic-openssl-v1",
				Connection: connKey,
				Direction:  "read",
				Local:      "127.0.0.1:443",
				Client:     "192.0.2.1:4321",
				Data:       []byte("GET / HTTP/1.1\r\nHost: test\r\nX-Traffic-Request-ID: " + reqID + "\r\n\r\n"),
			},
			ProcessID: identity,
		}
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	// Queue a burst of 20 datagrams right before requesting stop.
	for i := 1; i <= 20; i++ {
		if _, err := sender.Write(encodeEvent(uint64(i), strconv.Itoa(i))); err != nil {
			t.Fatalf("write %d before stop: %v", i, err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("capturePreload returned error: %v", err)
	}
	// After stop/drain, connected sender writes must fail and never appear in stream.jsonl.
	if _, err := sender.Write(encodeEvent(21, "after-stop")); err == nil {
		t.Fatal("expected connected unixgram write to fail after preload stop")
	}
	if err := recorder.close(); err != nil {
		t.Fatal(err)
	}
	if err := finishCaptureStateReason(store, false, false, false, "signal"); err != nil {
		t.Fatal(err)
	}

	if store.stats.DrainState != "unverified" {
		t.Fatalf("expected preload DrainState=unverified without final sender sequence confirmation, got %s", store.stats.DrainState)
	}
	exit, ok := store.stats.ProbeExits["openssl-preload"]
	if !ok || exit.DataDrained || !exit.TransportDetached {
		t.Fatalf("unexpected preload ProbeExit: ok=%v exit=%+v", ok, exit)
	}
	if store.stats.GapCounts["openssl-preload/drain_unconfirmed/shutdowns"] != 1 {
		t.Fatalf("missing drain_unconfirmed gap: %+v", store.stats.GapCounts)
	}

	raw, err := os.ReadFile(filepath.Join(store.dir, "tls", "stream.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("after-stop")) {
		t.Fatal("post-stop preload event entered stream.jsonl")
	}
	dataCount := 0
	sawEnd := false
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var ev session.RawEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Type == "data" {
			dataCount++
		}
		if ev.Type == "end" && ev.Reason == "probe_stopped" {
			sawEnd = true
		}
	}
	if dataCount != 20 || !sawEnd {
		t.Fatalf("persisted %d preload data events (want 20), sawEnd=%v", dataCount, sawEnd)
	}
}
