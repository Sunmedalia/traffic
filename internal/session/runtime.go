package session

import (
	"fmt"
	"os"
	"path/filepath"
)

// RuntimeRoot keeps portable installs independent of the launcher's working directory.
// Source builds under bin retain the repository's existing sessions directory.
func RuntimeRoot() string {
	executable, err := os.Executable()
	if err != nil {
		return "."
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	root := filepath.Dir(executable)
	if filepath.Base(root) == "bin" {
		root = filepath.Dir(root)
	}
	return root
}

func DefaultDataDir() string { return filepath.Join(RuntimeRoot(), "sessions") }

// InitRuntime creates storage only; it never starts capture or installs dependencies.
func InitRuntime() error { return initRuntimeAt(RuntimeRoot()) }

func initRuntimeAt(root string) error {
	PrivateUmask()
	for _, name := range []string{"sessions", "exports"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("create runtime directory %s: %w", path, err)
		}
	}
	return nil
}
