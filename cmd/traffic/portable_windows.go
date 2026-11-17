package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func grantProbeRuntimeAccess(path string) error {
	// Only the runtime subtree, not the application or sessions, is readable by IIS.
	if iisProbe == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "config", "applicationHost.config")); err != nil {
		return nil
	}
	output, err := exec.Command("icacls.exe", path, "/grant", "*S-1-5-32-568:(OI)(CI)RX").CombinedOutput()
	if err != nil {
		return fmt.Errorf("prepare IIS runtime access: %w: %s", err, output)
	}
	return nil
}
