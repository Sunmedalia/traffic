//go:build !linux

package main

import "fmt"

func inCaptureNamespace(fn func() error) error {
	if networkNamespacePID != 0 {
		return fmt.Errorf("--netns-pid requires Linux")
	}
	return fn()
}
