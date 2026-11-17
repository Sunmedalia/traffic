//go:build !windows

package main

func grantProbeRuntimeAccess(string) error { return nil }
