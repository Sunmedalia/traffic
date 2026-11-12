//go:build !windows

package main

import (
	"os"
	"os/exec"
	"runtime"

	"github.com/google/gopacket/pcap"
)

func doctorReport(devices []pcap.Interface, service string, pid int, library, probePath string) map[string]any {
	maps, _ := exec.Command("sh", "-c", "for p in $(pgrep -x nginx); do echo PID=$p; grep libssl /proc/$p/maps | head -1; done").Output()
	_, btf := os.Stat("/sys/kernel/btf/vmlinux")
	_, probe := os.Stat(probePath)
	return map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "root": os.Geteuid() == 0, "btf": btf == nil, "ecapture_installed": probe == nil, "nginx": string(maps), "interfaces": devices, "targets": discoverTargets("/proc", service, pid, library), "tls_verified": false}
}
