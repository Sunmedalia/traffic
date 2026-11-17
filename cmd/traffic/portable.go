package main

import (
	"github.com/Sunmedalia/traffic/internal/session"
	"os"
	"path/filepath"
	"runtime"
)

type portableProbePaths struct{ iis, openssl, python, runtime string }

func portableDefaults() portableProbePaths {
	result := portableProbePaths{python: "python"}
	if runtime.GOOS != "windows" {
		return result
	}
	result.python = session.BundleFile("deps/python/python.exe", "python")
	result.iis = session.BundleFile("deps/probes/probe-iis.py", "")
	result.openssl = session.BundleFile("deps/probes/probe-openssl.py", "")
	if result.iis != "" || result.openssl != "" {
		result.runtime = filepath.Join(session.RuntimeRoot(), "runtime", "frida")
	}
	return result
}
func isPortableProbeRuntime(path string) bool {
	return filepath.Clean(path) == filepath.Join(session.RuntimeRoot(), "runtime", "frida")
}
func preparePortableProbeRuntime() error {
	if runtime.GOOS != "windows" || (iisProbe == "" && opensslProbe == "") || !isPortableProbeRuntime(iisRuntime) {
		return nil
	}
	if err := os.MkdirAll(iisRuntime, 0700); err != nil {
		return err
	}
	return grantProbeRuntimeAccess(iisRuntime)
}
