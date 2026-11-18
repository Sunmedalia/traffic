package main

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const privateECaptureQueueSupported = true

func dialPrivateECaptureQueue(ctx context.Context, socket string, probePID int) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	pid, err := unixPeerPID(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if pid != probePID {
		conn.Close()
		return nil, fmt.Errorf("%w: peer pid %d, probe pid %d", errECaptureQueuePeer, pid, probePID)
	}
	return conn, nil
}

func unixPeerPID(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("eCapture queue is not a Unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return int(cred.Pid), nil
}
