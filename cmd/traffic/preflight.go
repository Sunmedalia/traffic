package main

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Sunmedalia/traffic/internal/session"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

type captureCheck struct {
	Target  string `json:"target,omitempty"`
	Backend string `json:"backend"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
}

func requireCaptureChecks(checks []captureCheck) error {
	if len(checks) == 0 {
		return fmt.Errorf("TLS preflight: no selected targets")
	}
	for _, check := range checks {
		if check.Status != "candidate" {
			return fmt.Errorf("TLS preflight %s/%s: %s", check.Target, check.Backend, check.Reason)
		}
	}
	return nil
}
func readableFile(path string) bool {
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	defer f.Close()
	st, e := f.Stat()
	return e == nil && st.Mode().IsRegular()
}
func captureChecks(service string, pid int, library, probe string, java bool, jar, preload string, javaPID int) []captureCheck {
	root := "/proc"
	if runtime.GOOS == "windows" {
		root = ""
	}
	if preload != "" {
		if !filepath.IsAbs(preload) {
			return []captureCheck{{Backend: "openssl-preload", Status: "unavailable", Reason: "preload socket path must be absolute"}}
		}
		if _, err := os.Lstat(preload); !os.IsNotExist(err) {
			return []captureCheck{{Backend: "openssl-preload", Status: "unavailable", Reason: "preload socket path must not already exist"}}
		}
		return []captureCheck{{Backend: "openssl-preload", Status: "candidate", Reason: "requires startup-loaded library; capture cannot verify loaded senders or complete coverage"}}
	}
	if networkNamespacePID != 0 {
		if err := inCaptureNamespace(func() error { return nil }); err != nil {
			return []captureCheck{{Backend: "packet", Status: "unavailable", Reason: err.Error()}}
		}
	}
	targets := discoverTargets(root, service, pid, library)
	checks := make([]captureCheck, 0, len(targets))
	for _, target := range targets {
		if pid == 0 {
			inScope := false
			for _, port := range target.Ports {
				if capturePorts[port] {
					inScope = true
					break
				}
			}
			if !inScope {
				continue
			}
		}
		c := captureCheck{Target: target.ID, Status: "unavailable", Reason: "no supported plaintext backend; HTTP packet capture can continue"}
		switch {
		case runtime.GOOS == "windows":
			c.Backend = "openssl"
			helper := opensslProbe
			if target.Service == "iis" {
				c.Backend = "iis-httpapi"
				helper = iisProbe
			}
			_, pythonErr := exec.LookPath(iisPython)
			if helper == "" {
				c.Reason = "probe is not explicitly enabled"
			} else if !readableFile(helper) || !readableFile(filepath.Join(filepath.Dir(helper), "probe-iis.py")) {
				c.Reason = "probe helper files are not readable"
			} else if pythonErr != nil {
				c.Reason = "Python executable is unavailable"
			} else if st, e := os.Stat(iisRuntime); (e != nil || !st.IsDir()) && !isPortableProbeRuntime(iisRuntime) {
				c.Reason = "probe runtime directory is unavailable"
			} else if reason := windowsProbeDependencyReason(helper); reason != "" {
				c.Reason = reason
			} else {
				c.Status = "candidate"
				c.Reason = "Frida dependency checked; attach permissions, target ABI and runtime access require verification"
			}
		case target.Service == "tomcat" && target.Library == "":
			c.Backend = "java-agent"
			if !java || (javaPID > 0 && target.PID != javaPID) {
				c.Reason = "Java attachment requires explicit opt-in"
			} else if !readableFile(jar) {
				c.Reason = "Java agent archive is not readable"
			} else {
				c.Status = "candidate"
				c.Reason = "Tomcat NIO only; JVM attach permission and loaded classes require runtime verification"
			}
		default:
			c.Backend = "ecapture-openssl"
			st, e := os.Stat(probe)
			if runtime.GOOS != "linux" {
				c.Reason = "eBPF backend requires Linux"
			} else if target.Library == "" || !readableFile(target.Library) {
				c.Reason = "mapped OpenSSL library is unavailable"
			} else if e != nil || st.IsDir() || st.Mode()&0111 == 0 {
				c.Reason = "eCapture executable is unavailable"
			} else if reason := linuxLibraryReason(target.Library, probe); reason != "" {
				c.Reason = reason
			} else if !readableFile("/sys/kernel/btf/vmlinux") {
				c.Reason = "CO-RE BTF is unavailable; startup-loaded preload is a separate opt-in"
			} else if os.Geteuid() != 0 {
				c.Reason = "current backend requires privileged BPF access"
			} else {
				c.Status = "candidate"
				c.Reason = "library ABI, BPF policy and probe build must be verified at attachment; no coverage guarantee"
			}
		}
		checks = append(checks, c)
	}
	return checks
}

func linuxLibraryReason(path, probe string) string {
	file, err := elf.Open(path)
	if err != nil {
		return "mapped library is not a readable ELF binary"
	}
	defer file.Close()
	if (runtime.GOARCH == "amd64" && file.Machine != elf.EM_X86_64) || (runtime.GOARCH == "arm64" && file.Machine != elf.EM_AARCH64) {
		return "mapped library architecture differs from collector"
	}
	names, _ := file.DynString(elf.DT_SONAME)
	supported := false
	for _, name := range names {
		if name == "libssl.so.3" {
			supported = true
		}
		if name == "libssl.so.1.1" {
			section := file.Section(".rodata")
			if section == nil {
				return "cannot identify OpenSSL 1.1.1 ABI without a version string"
			}
			data, err := io.ReadAll(io.LimitReader(section.Open(), 4<<20))
			if err != nil || !openssl111Version.Match(data) {
				return "OpenSSL 1.1 library is outside the bundled 1.1.1a-w ABI range"
			}
			if !probeCapability(probe, "1.1.1") {
				return "rebuild eCapture with 1.1.1 probes and its matching .traffic.json capability manifest"
			}
			supported = true
		}
	}
	if !supported {
		return "bundled CO-RE probes cover OpenSSL 3; this library ABI requires a separately verified backend"
	}
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return "cannot inspect exported OpenSSL symbols"
	}
	exports := map[string]bool{}
	for _, symbol := range symbols {
		if symbol.Section != elf.SHN_UNDEF {
			exports[symbol.Name] = true
		}
	}
	if !(exports["SSL_read"] && exports["SSL_write"] || exports["SSL_read_ex"] && exports["SSL_write_ex"]) {
		return "supported OpenSSL read/write API pair is missing"
	}
	return ""
}
func windowsProbeDependencyReason(helper string) string {
	dir := filepath.Dir(helper)
	script := "openssl-plaintext.js"
	if helper == iisProbe {
		script = "iis-plaintext.js"
	}
	if !readableFile(filepath.Join(dir, script)) {
		return "plaintext probe JavaScript is not readable"
	}
	if script == "openssl-plaintext.js" {
		path := opensslProfile
		if path == "" {
			path = filepath.Join(dir, "openssl-profiles.json")
		}
		file, err := os.Open(path)
		if err != nil {
			return "OpenSSL profile is not readable"
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		var profiles []map[string]any
		if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &profiles) != nil || profiles == nil {
			return "OpenSSL profile must be a valid bounded JSON array"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, iisPython, "-c", "import frida; print(frida.__version__)").Output()
	if err != nil {
		return "cannot import Frida using configured Python"
	}
	if strings.TrimSpace(string(output)) != "17.5.1" {
		return "Frida version differs from validated 17.5.1"
	}
	return ""
}

func (s *Store) checkTarget(target session.Target) captureCheck {
	s.checkMu.Lock()
	defer s.checkMu.Unlock()
	if s.probeCheck == nil {
		return captureCheck{Target: target.ID, Status: "candidate"}
	}
	if s.checks == nil {
		s.checks = map[string]captureCheck{}
	}
	key := target.ID + "|" + target.Library
	if check, ok := s.checks[key]; ok {
		return check
	}
	check := s.probeCheck(target)
	if len(s.checks) >= 1024 {
		for old := range s.checks {
			delete(s.checks, old)
			break
		}
	}
	s.checks[key] = check
	if check.Status != "candidate" {
		s.problem(fmt.Errorf("TLS preflight %s/%s: %s", target.ID, check.Backend, check.Reason))
	}
	return check
}

var openssl111Version = regexp.MustCompile(`OpenSSL 1\.1\.1[a-w]\b`)

type probeMetadata struct {
	SchemaVersion int      `json:"schema_version"`
	SHA256        string   `json:"sha256"`
	ABIs          []string `json:"openssl_abis"`
	Features      []string `json:"features,omitempty"`
}
type validatedProbe struct {
	binary, manifest os.FileInfo
	metadata         probeMetadata
	valid            bool
}

var probeCapabilityCache = struct {
	sync.Mutex
	entries map[string]validatedProbe
}{entries: map[string]validatedProbe{}}

func probeCapability(binary, abi string) bool {
	file, err := os.Open(binary + ".traffic.json")
	if err != nil {
		return false
	}
	defer file.Close()
	manifestInfo, err := file.Stat()
	if err != nil {
		return false
	}
	input, err := os.Open(binary)
	if err != nil {
		return false
	}
	defer input.Close()
	binaryInfo, err := input.Stat()
	if err != nil {
		return false
	}
	probeCapabilityCache.Lock()
	defer probeCapabilityCache.Unlock()
	same := func(a, b os.FileInfo) bool {
		return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
	}
	cached, ok := probeCapabilityCache.entries[binary]
	if !ok || !same(cached.binary, binaryInfo) || !same(cached.manifest, manifestInfo) {
		var metadata probeMetadata
		if err := json.NewDecoder(io.LimitReader(file, 64<<10)).Decode(&metadata); err != nil || metadata.SchemaVersion != 1 {
			return false
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, input); err != nil {
			return false
		}
		cached = validatedProbe{binary: binaryInfo, manifest: manifestInfo, metadata: metadata, valid: metadata.SHA256 == hex.EncodeToString(hash.Sum(nil))}
		if len(probeCapabilityCache.entries) >= 64 {
			for old := range probeCapabilityCache.entries {
				delete(probeCapabilityCache.entries, old)
				break
			}
		}
		probeCapabilityCache.entries[binary] = cached
	}
	if !cached.valid {
		return false
	}
	values := cached.metadata.ABIs
	if feature, ok := strings.CutPrefix(abi, "feature:"); ok {
		abi = feature
		values = cached.metadata.Features
	}
	for _, value := range values {
		if value == abi {
			return true
		}
	}
	return false
}
