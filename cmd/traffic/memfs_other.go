//go:build !linux

package main

func memoryBackedFilesystem(string) (string, bool) { return "", false }
