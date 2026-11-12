package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/Sunmedalia/traffic/internal/session"
	"golang.org/x/sys/windows"
)

func processIdentity(_ string, pid int) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", pid, uint64(created.HighDateTime)<<32|uint64(created.LowDateTime)), nil
}

func processTarget(root string, pid int) (session.Target, error) {
	target := session.Target{PID: pid, UID: -1, GID: -1, Service: "unknown", State: "https-unverified"}
	id, err := processIdentity(root, pid)
	if err != nil {
		return target, err
	}
	target.ID = id
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return target, err
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return target, err
	}
	if strings.EqualFold(filepath.Base(windows.UTF16ToString(buffer[:size])), "w3wp.exe") {
		target.Service = "iis"
	}
	return target, nil
}

// IIS listeners belong to HTTP.sys, not to the individual worker process.
// Bindings describe candidate service ports without inventing worker ownership.
func iisPorts() []int {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "config", "applicationHost.config")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var config struct {
		Bindings []struct {
			Protocol string `xml:"protocol,attr"`
			Info     string `xml:"bindingInformation,attr"`
		} `xml:"system.applicationHost>sites>site>bindings>binding"`
	}
	if xml.Unmarshal(data, &config) != nil {
		return nil
	}
	set := map[int]bool{}
	for _, binding := range config.Bindings {
		if binding.Protocol != "http" && binding.Protocol != "https" {
			continue
		}
		parts := strings.Split(binding.Info, ":")
		if len(parts) < 3 {
			continue
		}
		port, err := strconv.Atoi(parts[len(parts)-2])
		if err == nil {
			set[port] = true
		}
	}
	var ports []int
	for port := range set {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func discoverTargets(root, service string, selectedPID int, _ string) []session.Target {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var targets []session.Target
	ports := iisPorts()
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if selectedPID > 0 && int(entry.ProcessID) != selectedPID {
			continue
		}
		if selectedPID == 0 && !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "w3wp.exe") {
			continue
		}
		target, err := processTarget(root, int(entry.ProcessID))
		if err != nil || (service != "auto" && target.Service != service) {
			continue
		}
		if target.Service == "iis" {
			target.Ports = ports
		}
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].PID < targets[j].PID })
	return targets
}

func captureServices(ctx context.Context, s *Store, _ *HTTPProcessor, _, _, service string, pid int, _ bool, _, _ string, _ int) {
	if iisProbe != "" {
		captureWindowsIIS(ctx, s, service, pid)
		return
	}
	s.problem(fmt.Errorf("Windows IIS HTTPS plaintext is unverified; use scripts/windows/probe-iis.py for the dynamic API experiment"))
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		targets := discoverTargets("", service, pid, "")
		s.mu.Lock()
		s.stats.TLS = "unavailable"
		s.stats.Targets = targets
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
