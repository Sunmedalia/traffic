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

func publishAnalysis(ctx context.Context, dir, source string) error {
	if err := validateAnalysisDestination(dir); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	suffix := hex.EncodeToString(nonce[:])
	name := "analysis-" + suffix + ".sqlite"
	dest, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			root.Remove(name)
		}
	}()
	input, err := os.Open(filepath.Join(source, "analysis.sqlite"))
	if err != nil {
		dest.Close()
		return err
	}
	defer input.Close()
	_, err = io.Copy(dest, contextReader{ctx, input})
	if err == nil {
		err = dest.Sync()
	}
	closed := dest.Close()
	if err == nil {
		err = closed
	}
	if err != nil {
		return err
	}
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
	closed = file.Close()
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
	// Cleanup only generations older than a day. A brief reader-open retry handles
	// a concurrent cleanup; already-open immutable readers keep their own snapshot.
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if analysisGeneration.MatchString(entry.Name()) && entry.Name() != name {
			info, statErr := entry.Info()
			if statErr == nil && time.Since(info.ModTime()) > 24*time.Hour {
				_ = root.Remove(entry.Name())
			}
		}
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
