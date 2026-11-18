//go:build !linux

package main

import (
	"context"
	"errors"
	"net"
)

const privateECaptureQueueSupported = false

func startPrivateQueueGuard() (string, func() error, error) {
	return "", nil, errors.New("private eCapture queue requires Linux")
}

func dialPrivateECaptureQueue(context.Context, string, int) (net.Conn, error) {
	return nil, errors.New("private eCapture queue requires Linux")
}
