//go:build !linux

package main

import "errors"

// Only Linux has sock_diag; discovery reads the /proc socket tables instead.
func kernelListeners(string) (map[string]int, error) {
	return nil, errors.New("sock_diag requires Linux")
}
