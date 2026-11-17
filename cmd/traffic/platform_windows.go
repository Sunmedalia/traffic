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
	backend := "iis-httpapi"
	if opensslProbe != "" {
		backend = "openssl"
		if iisProbe != "" {
			backend = "iis-httpapi,openssl"
		}
	}
	return map[string]any{
		"packet_backend": func() string {
			if winDivertPath() != "" {
				return "windivert-sniff"
			}
			return "npcap"
		}(),
		"bundled_packet_driver": winDivertPath(),
		"packet_drop_counter":   "WinDivert queue drops are not exposed; completeness remains unverified",
		"os":                    runtime.GOOS, "arch": runtime.GOARCH,
		"administrator":   windows.GetCurrentProcessToken().IsElevated(),
		"npcap_installed": npcap == nil, "iis_installed": iis == nil,
		"interfaces": devices, "targets": discoverTargets("", service, pid, library),
		"tls_verified": false, "tls_backend": backend, "tls_backends": []string{"iis-httpapi", "openssl"}, "tls_configured": iisProbe != "" || opensslProbe != "",
		"tls_state": "bundled probes are configured automatically; capture attaches to selected services, doctor does not attach",
	}
}
