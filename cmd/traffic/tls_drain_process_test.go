//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHelperECaptureProbeProcess(t *testing.T) {
	if os.Getenv("TRAFFIC_FAKE_ECAPTURE_SUBPROCESS") != "1" {
		return
	}
	pidFile := os.Getenv("TRAFFIC_FAKE_ECAPTURE_PID_FILE")
	if pidFile != "" {
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600)
	}
	targetPID, _ := strconv.Atoi(os.Getenv("TRAFFIC_FAKE_ECAPTURE_TARGET_PID"))
	var wsURL string
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "--ecaptureq" && i+1 < len(os.Args) {
			wsURL = os.Args[i+1]
			break
		}
	}
	if urlFile := os.Getenv("TRAFFIC_FAKE_ECAPTURE_URL_FILE"); urlFile != "" {
		_ = os.WriteFile(urlFile, []byte(wsURL), 0600)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	var listener net.Listener
	var err error
	if socket, ok := strings.CutPrefix(wsURL, "unix://"); ok {
		listener, err = net.Listen("unix", socket)
	} else {
		listener, err = net.Listen("tcp", strings.TrimSuffix(strings.TrimPrefix(wsURL, "ws://"), "/"))
	}
	if err != nil {
		os.Exit(1)
	}
	defer listener.Close()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	connCh := make(chan *websocket.Conn, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if c, err := upgrader.Upgrade(w, r, nil); err == nil {
			connCh <- c
		}
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()

	ws := <-connCh
	defer ws.Close()
	_ = ws.WriteMessage(websocket.BinaryMessage, encodeFakeProcessLog("traffic-control-v1:ready"))
	_ = ws.WriteMessage(websocket.BinaryMessage, encodeFakeTLSEvent(1, targetPID, fmt.Sprintf("%d_inode_1", targetPID), "read", []byte("GET /subproc/1 HTTP/1.1\r\n\r\n")))
	<-sigCh
	_ = ws.WriteMessage(websocket.BinaryMessage, encodeFakeTLSEvent(2, targetPID, fmt.Sprintf("%d_inode_1", targetPID), "read", []byte("GET /subproc/2 HTTP/1.1\r\n\r\n")))
	_ = ws.WriteMessage(websocket.BinaryMessage, encodeFakeProcessLog("traffic-control-v1:drained:seq=2,dropped=0,perf_lost=0"))
	_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	os.Exit(0)
}

func TestCaptureTLSSubprocessEndToEndDrain(t *testing.T) {
	probeListen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback tcp listen unavailable in current sandbox: %v", err)
	}
	dialCheck, dialErr := net.DialTimeout("tcp", probeListen.Addr().String(), 200*time.Millisecond)
	probeListen.Close()
	if dialErr != nil {
		t.Skipf("loopback tcp dial unavailable in current sandbox: %v", dialErr)
	}
	dialCheck.Close()
	runCaptureTLSSubprocessDrain(t, false)
}

// A private_eventq_v1 build must be read over its private Unix socket.
func TestCaptureTLSSubprocessPrivateQueueDrain(t *testing.T) {
	if !privateECaptureQueueSupported {
		t.Skip("private eCapture queue requires Linux")
	}
	if url := runCaptureTLSSubprocessDrain(t, true); !strings.HasPrefix(url, "unix:///") {
		t.Fatalf("probe was given %q", url)
	}
}

func runCaptureTLSSubprocessDrain(t *testing.T, privateQueue bool) string {
	oldPorts, oldDrain, oldStop := capturePorts, drainTimeout, stopTimeout
	capturePorts = map[int]bool{443: true}
	drainTimeout = 3 * time.Second
	stopTimeout = 5 * time.Second
	defer func() {
		capturePorts, drainTimeout, stopTimeout = oldPorts, oldDrain, oldStop
	}()

	dir := t.TempDir()
	s, err := openStore(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	recorder := newRecorder(s)
	pidFile := filepath.Join(t.TempDir(), "subproc.pid")
	targetPID := os.Getpid()
	targetID := fmt.Sprintf("%d:999", targetPID)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(t.TempDir(), "fake-ecapture.sh")
	urlFile := filepath.Join(t.TempDir(), "queue.url")
	script := fmt.Sprintf("#!/bin/sh\nexport TRAFFIC_FAKE_ECAPTURE_SUBPROCESS=1\nexport TRAFFIC_FAKE_ECAPTURE_PID_FILE=%q\nexport TRAFFIC_FAKE_ECAPTURE_TARGET_PID=%d\nexport TRAFFIC_FAKE_ECAPTURE_URL_FILE=%q\nexec %q -test.run=^TestHelperECaptureProbeProcess$ -- \"$@\"\n",
		pidFile, targetPID, urlFile, exe)
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if privateQueue {
		writeQueueFeature(t, scriptPath)
	}

	ctx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- captureTLS(ctx, s, recorder, scriptPath, "/lib/libssl.so.3", targetPID, 0, "ecapture/subprocess",
			func(pid int, _ string) string {
				if pid == targetPID {
					return targetID
				}
				return ""
			},
			nil,
			func() {
				select {
				case readyCh <- struct{}{}:
				default:
				}
			},
		)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		default:
		}
	}()

	select {
	case <-readyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("subprocess probe did not report ready")
	}
	cancel()
	var runErr error
	exceeded, closeErr := shutdownWithin(func() { runErr = <-done }, recorder.close, stopTimeout)
	if exceeded || closeErr != nil || runErr != nil {
		t.Fatalf("exceeded=%v closeErr=%v runErr=%v", exceeded, closeErr, runErr)
	}
	_ = finishCaptureStateReason(s, false, false, exceeded, "signal")
	rawPID, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	childPID, _ := strconv.Atoi(strings.TrimSpace(string(rawPID)))
	if err := syscall.Kill(childPID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("child pid %d still running", childPID)
	}
	if s.stats.DrainState != "confirmed" {
		t.Fatalf("expected confirmed DrainState, got %+v", s.stats)
	}
	url, err := os.ReadFile(urlFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(url)
}
