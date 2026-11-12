package main

import (
	"context"
	"encoding/binary"
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
	target.Service = windowsServiceName(filepath.Base(windows.UTF16ToString(buffer[:size])))
	return target, nil
}

func windowsServiceName(name string) string {
	switch strings.ToLower(name) {
	case "w3wp.exe":
		return "iis"
	case "nginx.exe":
		return "nginx"
	case "httpd.exe", "apache.exe", "apache2.exe":
		return "apache"
	default:
		return "unknown"
	}
}

// Query ownership from the TCP stack rather than guessing service ports.
func windowsListeningPorts() map[int][]int {
	result := make(map[int][]int)
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
		var size uint32
		proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), 3, 0)
		if size < 4 || size > 16<<20 {
			continue
		}
		buffer := make([]byte, size)
		status, _, _ := proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), 3, 0)
		if status != 0 {
			continue
		}
		rowSize, portOffset, pidOffset := 24, 8, 20
		if family == windows.AF_INET6 {
			rowSize, portOffset, pidOffset = 56, 20, 52
		}
		count := int(binary.LittleEndian.Uint32(buffer))
		for index := 0; index < count && 4+(index+1)*rowSize <= len(buffer); index++ {
			row := buffer[4+index*rowSize : 4+(index+1)*rowSize]
			pid := int(binary.LittleEndian.Uint32(row[pidOffset:]))
			port := int(binary.BigEndian.Uint16(row[portOffset:]))
			exists := false
			for _, previous := range result[pid] {
				if previous == port {
					exists = true
				}
			}
			if !exists {
				result[pid] = append(result[pid], port)
			}
		}
	}
	for _, ports := range result {
		sort.Ints(ports)
	}
	return result
}

func windowsTLSLibrary(pid int) string {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ModuleEntry32{Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{}))}
	for err = windows.Module32First(snapshot, &entry); err == nil; err = windows.Module32Next(snapshot, &entry) {
		name := windows.UTF16ToString(entry.Module[:])
		lower := strings.ToLower(name)
		if strings.Contains(lower, "libssl") || lower == "ssleay32.dll" {
			return name
		}
	}
	return ""
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

func discoverTargets(root, service string, selectedPID int, library string) []session.Target {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var targets []session.Target
	ports := iisPorts()
	listeners := windowsListeningPorts()
	parents := make(map[int]int)
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if selectedPID > 0 && int(entry.ProcessID) != selectedPID {
			continue
		}
		if selectedPID == 0 && windowsServiceName(windows.UTF16ToString(entry.ExeFile[:])) == "unknown" {
			continue
		}
		target, err := processTarget(root, int(entry.ProcessID))
		if service == "openssl" && selectedPID > 0 {
			target.Service = "openssl"
		}
		if err != nil || (service != "auto" && target.Service != service) {
			continue
		}
		parents[target.PID] = int(entry.ParentProcessID)
		target.Ports = listeners[target.PID]
		target.Library = library
		if target.Library == "" {
			target.Library = windowsTLSLibrary(target.PID)
		}
		if target.Library != "" {
			target.State = "discovered"
		}
		if target.Service == "iis" {
			target.Ports = ports
		}
		targets = append(targets, target)
	}
	for index := range targets {
		if len(targets[index].Ports) == 0 {
			targets[index].Ports = listeners[parents[targets[index].PID]]
		}
	}
	if selectedPID == 0 {
		// Windows Nginx and Apache masters delegate requests to child processes.
		// Keep the parent's listener ports above, but instrument the workers.
		masters := make(map[int]bool)
		for _, child := range targets {
			for _, parent := range targets {
				if parents[child.PID] == parent.PID && child.Service == parent.Service && (child.Service == "nginx" || child.Service == "apache") {
					masters[parent.PID] = true
				}
			}
		}
		workers := targets[:0]
		for _, target := range targets {
			if !masters[target.PID] {
				workers = append(workers, target)
			}
		}
		targets = workers
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].PID < targets[j].PID })
	return targets
}

func captureServices(ctx context.Context, s *Store, p *HTTPProcessor, _, library, service string, pid int, _ bool, _, _ string, _ int) {
	if iisProbe != "" || opensslProbe != "" {
		captureWindowsServices(ctx, s, p, service, pid, library)
		return
	}
	s.problem(fmt.Errorf("Windows HTTPS probes are disabled; enable --iis-probe or --openssl-probe for plaintext capture"))
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		targets := discoverTargets("", service, pid, library)
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
