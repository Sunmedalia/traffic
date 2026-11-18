package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrivateECaptureQueueRejectsForeignPeer(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "q.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// The listener lives in this test process, so any other PID is a foreign
	// server that must not be read from.
	if conn, err := dialPrivateECaptureQueue(ctx, socket, os.Getpid()+1); !errors.Is(err, errECaptureQueuePeer) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("foreign peer accepted: %v", err)
	}
	conn, err := dialPrivateECaptureQueue(ctx, socket, os.Getpid())
	if err != nil {
		t.Fatalf("owning peer rejected: %v", err)
	}
	conn.Close()
}

func TestECaptureQueueEndpointRequiresCapabilityForPrivateSocket(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "ecapture")
	if err := os.WriteFile(bin, []byte("queue capability fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	legacy, err := newECaptureQueueEndpoint(nil, bin)
	if err != nil {
		t.Fatal(err)
	}
	legacy.cleanup()
	if legacy.socket != "" || !strings.HasPrefix(legacy.listen, "ws://127.0.0.1:") {
		t.Fatalf("legacy build got %+v", legacy)
	}
	writeQueueFeature(t, bin)
	private, err := newECaptureQueueEndpoint(nil, bin)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(private.socket))
	if err != nil || info.Mode().Perm() != 0700 || private.listen != "unix://"+private.socket {
		t.Fatalf("private endpoint %+v dir=%v err=%v", private, info, err)
	}
	private.cleanup()
	if _, err := os.Stat(filepath.Dir(private.socket)); !os.IsNotExist(err) {
		t.Fatalf("queue directory not removed: %v", err)
	}
}

func writeQueueFeature(t *testing.T, bin string) {
	t.Helper()
	binary, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	metadata := fmt.Sprintf(`{"schema_version":1,"sha256":"%s","openssl_abis":["3.0"],"features":["private_eventq_v1"]}`, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(bin+".traffic.json", []byte(metadata), 0600); err != nil {
		t.Fatal(err)
	}
}
