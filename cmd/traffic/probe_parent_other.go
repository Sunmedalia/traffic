//go:build !linux

package main

import "os/exec"

func bindProbeParent(*exec.Cmd) func() { return func() {} }
