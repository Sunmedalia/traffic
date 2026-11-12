package main

import (
	"fmt"
	"github.com/Sunmedalia/traffic/internal/session"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

func validDirectoryName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 80 {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("-_.", r) {
			return false
		}
	}
	return true
}

// An explicit output retains its exact path. Automatic sessions are reserved with
// Mkdir so simultaneous captures cannot share a session, even in the same second.
func prepareOutputDir(output, root, name, host string, started time.Time) (string, error) {
	if !validDirectoryName(name) {
		return "", fmt.Errorf("invalid --name %q, use up to 80 bytes of letters, digits, hyphens, underscores or dots", name)
	}
	if output != "" {
		absolute, err := filepath.Abs(output)
		if err != nil {
			return "", err
		}
		if err = os.MkdirAll(absolute, 0700); err != nil {
			return "", err
		}
		if err := session.RestrictDirectory(absolute); err != nil {
			return "", err
		}
		return absolute, nil
	}
	if root == "" {
		return "", fmt.Errorf("--data-dir must not be empty")
	}
	host = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_.", r) {
			return r
		}
		return '-'
	}, host)
	host = strings.Trim(host, "-_.")
	if host == "" {
		host = "unknown-host"
	}
	parent, err := filepath.Abs(filepath.Join(root, host, started.Format("2006-01-02")))
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(parent, 0700); err != nil {
		return "", err
	}
	base := started.Format("15-04-05") + "-" + name
	for suffix := 0; ; suffix++ {
		leaf := base
		if suffix > 0 {
			leaf = fmt.Sprintf("%s-%02d", base, suffix+1)
		}
		dir := filepath.Join(parent, leaf)
		if err = os.Mkdir(dir, 0700); os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := session.RestrictDirectory(dir); err != nil {
			return "", err
		}
		return dir, nil
	}
}
