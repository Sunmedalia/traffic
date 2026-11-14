//go:build !linux

package main

import (
	"context"
	"fmt"
)

func capturePreload(_ context.Context, _ *Store, _ *HTTPProcessor, _ string) error {
	return fmt.Errorf("OpenSSL preload capture requires Linux")
}
