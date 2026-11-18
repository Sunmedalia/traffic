package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/websocket"
)

// errECaptureQueuePeer reports a queue socket served by a process other than
// the eCapture child this collector started.
var errECaptureQueuePeer = errors.New("eCapture queue socket is not served by the started probe")

// eCaptureQueueEndpoint is where the collector reads decrypted events from
// eCapture. A private_eventq_v1 build listens on a 0600 Unix socket inside a
// fresh 0700 directory and the collector checks the socket's peer PID, so no
// other local user can subscribe to plaintext or impersonate the probe.
// Older builds only offer loopback TCP, which any local user can reach.
type eCaptureQueueEndpoint struct {
	listen  string
	url     string
	origin  string
	socket  string
	cleanup func()
}

func newECaptureQueueEndpoint(s *Store, bin string) (*eCaptureQueueEndpoint, error) {
	if privateECaptureQueueSupported && probeCapability(bin, "feature:private_eventq_v1") {
		dir, err := os.MkdirTemp("", "traffic-eq-")
		if err != nil {
			return nil, fmt.Errorf("%w: private queue directory: %w", errECaptureConfiguration, err)
		}
		socket := filepath.Join(dir, "q.sock")
		if len(socket) >= 104 {
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("%w: private queue socket path too long: %s", errECaptureConfiguration, socket)
		}
		return &eCaptureQueueEndpoint{
			listen:  "unix://" + socket,
			url:     "ws://ecapture/",
			origin:  "http://ecapture",
			socket:  socket,
			cleanup: func() { _ = os.RemoveAll(dir) },
		}, nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := listener.Addr().String()
	listener.Close()
	if s != nil {
		s.problem(errors.New("eCapture build lacks private_eventq_v1; decrypted events use an unauthenticated loopback TCP queue"))
	}
	return &eCaptureQueueEndpoint{
		listen:  "ws://" + addr + "/",
		url:     "ws://" + addr + "/",
		origin:  "http://" + addr,
		cleanup: func() {},
	}, nil
}

// dialer connects to the queue. For a private socket it accepts only a
// listener owned by probePID.
func (q *eCaptureQueueEndpoint) dialer(handshake time.Duration, probePID int) *websocket.Dialer {
	d := &websocket.Dialer{HandshakeTimeout: handshake}
	if q.socket != "" {
		socket := q.socket
		d.NetDialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialPrivateECaptureQueue(ctx, socket, probePID)
		}
	}
	return d
}
