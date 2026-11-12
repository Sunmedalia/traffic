package main

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/windows"
)

func doctorReport(devices []pcap.Interface, service string, pid int, library, _ string) map[string]any {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "Npcap", "wpcap.dll")
	_, npcap := os.Stat(path)
	_, iis := os.Stat(filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "config", "applicationHost.config"))
	return map[string]any{
		"os": runtime.GOOS, "arch": runtime.GOARCH,
		"administrator":   windows.GetCurrentProcessToken().IsElevated(),
		"npcap_installed": npcap == nil, "iis_installed": iis == nil,
		"interfaces": devices, "targets": discoverTargets("", service, pid, library),
		"tls_verified": false, "tls_backend": "iis-httpapi", "tls_configured": iisProbe != "",
		"tls_state": "opt-in with --iis-probe and --iis-runtime-dir; verify with real requests",
	}
}
