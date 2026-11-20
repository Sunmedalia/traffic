package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const analysisPointer = "analysis-current.json"

var analysisGeneration = regexp.MustCompile(`^analysis-[0-9a-f]{32}\.sqlite$`)

// A small atomic pointer selects an immutable database generation. Publishing
// never opens a session-supplied database for writing and never replaces a live
// SQLite reader (including on Windows, where readers can prevent replacement).
func validateAnalysisDestination(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range []string{"analysis.sqlite", "analysis.sqlite-journal", "analysis.sqlite-wal", "analysis.sqlite-shm", analysisPointer} {
		info, err := root.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("analysis paths must be regular files, not symlinks")
		}
	}
	return nil
}

func analysisDatabasePath(dir string) (string, error) {
	if err := validateAnalysisDestination(dir); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := root.Open(analysisPointer)
	if os.IsNotExist(err) {
		return filepath.Join(dir, "analysis.sqlite"), nil
	}
	if err != nil {
		return "", err
	}
	defer file.Close()
	var pointer struct {
		File string `json:"file"`
	}
	if err = json.NewDecoder(io.LimitReader(file, 1024)).Decode(&pointer); err != nil {
		return "", err
	}
	if !analysisGeneration.MatchString(pointer.File) {
		return "", errors.New("invalid analysis generation pointer")
	}
	info, err := root.Lstat(pointer.File)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("analysis generation must be a regular file")
	}
	return filepath.Join(dir, pointer.File), nil
}

func analysisExists(dir string) bool {
	path, err := analysisDatabasePath(dir)
	if err != nil {
		return true
	}
	_, err = os.Stat(path)
	return err == nil
}

// analysisBuild names unpublished generations. They are hidden, never
// selected by the pointer, and removed by publication or failure cleanup.
var analysisBuild = regexp.MustCompile(`^\.analysis-build-[0-9a-f]{32}\.sqlite$`)

func analysisNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

// createAnalysisBuild creates an empty build file inside dir and returns its name.
func createAnalysisBuild(dir string) (string, error) {
	if err := validateAnalysisDestination(dir); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	suffix, err := analysisNonce()
	if err != nil {
		return "", err
	}
	name := ".analysis-build-" + suffix + ".sqlite"
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	return name, file.Close()
}

// removeAnalysisBuild deletes a build left unpublished; it is a no-op afterwards.
func removeAnalysisBuild(dir, name string) {
	if !analysisBuild.MatchString(name) {
		return
	}
	if root, err := os.OpenRoot(dir); err == nil {
		_ = root.Remove(name)
		_ = root.Remove(name + "-journal")
		root.Close()
	}
}

// publishAnalysis syncs the finished build named build inside dir, renames it to
// a fresh immutable generation and atomically points analysis-current.json at it.
func publishAnalysis(ctx context.Context, dir, build string) error {
	if !analysisBuild.MatchString(build) {
		return errors.New("invalid analysis build name")
	}
	if err := validateAnalysisDestination(dir); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat(build)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("analysis build must be a regular file")
	}
	input, err := root.OpenFile(build, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = input.Sync()
	if closed := input.Close(); err == nil {
		err = closed
	}
	if err != nil {
		return err
	}
	suffix, err := analysisNonce()
	if err != nil {
		return err
	}
	name := "analysis-" + suffix + ".sqlite"
	if _, err = root.Lstat(name); !os.IsNotExist(err) {
		if err == nil {
			err = os.ErrExist
		}
		return err
	}
	if err = root.Rename(build, name); err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			root.Remove(name)
		}
	}()
	tmp := ".analysis-pointer-" + suffix + ".tmp"
	file, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	err = json.NewEncoder(file).Encode(map[string]string{"file": name})
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err == nil {
		err = closed
	}
	if err != nil {
		return err
	}
	if err = validateAnalysisDestination(dir); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = root.Rename(tmp, analysisPointer); err != nil {
		return err
	}
	published = true
	// Cleanup only generations and abandoned builds older than a day. A brief
	// reader-open retry handles a concurrent cleanup; already-open immutable
	// readers keep their own snapshot.
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		stale := analysisGeneration.MatchString(entry.Name()) && entry.Name() != name
		if analysisBuild.MatchString(entry.Name()) {
			stale = true
		}
		if stale {
			info, statErr := entry.Info()
			if statErr == nil && time.Since(info.ModTime()) > 24*time.Hour {
				_ = root.Remove(entry.Name())
			}
		}
	}
	return nil
}
