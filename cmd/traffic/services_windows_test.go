package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/Sunmedalia/traffic/internal/session"
)

func TestWindowsProcessIdentity(t *testing.T) {
	first, err := processTarget("", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	second, err := processIdentity("", os.Getpid())
	if err != nil || first.ID == "" || first.ID != second || first.PID != os.Getpid() {
		t.Fatalf("unstable process identity: %+v %q %v", first, second, err)
	}
	if _, err := processIdentity("", -1); err == nil {
		t.Fatal("invalid PID accepted")
	}
}

func TestIISBindingPorts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SystemRoot", root)
	dir := filepath.Join(root, "System32", "inetsrv", "config")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := `<configuration><system.applicationHost><sites><site><bindings>
<binding protocol="http" bindingInformation="*:8080:" />
<binding protocol="https" bindingInformation="[::1]:8443:traffic-lab" />
<binding protocol="http" bindingInformation="127.0.0.1:8080:other" />
<binding protocol="net.tcp" bindingInformation="9000:*" />
</bindings></site></sites></system.applicationHost></configuration>`
	if err := os.WriteFile(filepath.Join(dir, "applicationHost.config"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if ports := iisPorts(); !reflect.DeepEqual(ports, []int{8080, 8443}) {
		t.Fatalf("IIS binding ports %v", ports)
	}
	if https := iisHTTPSPorts(); !reflect.DeepEqual(https, []int{8443}) {
		t.Fatalf("IIS HTTPS binding ports %v", https)
	}
	if iisHasSelectedHTTPSPort(map[int]bool{8080: true}) || !iisHasSelectedHTTPSPort(map[int]bool{8443: true}) {
		t.Fatal("IIS HTTPS scope selection mismatch")
	}
}

func TestWindowsMiddlewareDiscovery(t *testing.T) {
	for name, expected := range map[string]string{"NGINX.EXE": "nginx", "httpd.exe": "apache", "apache2.exe": "apache", "w3wp.exe": "iis", "java.exe": "unknown"} {
		if got := windowsServiceName(name); got != expected {
			t.Fatalf("%s: %s", name, got)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, text, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(text)
	found := false
	for _, got := range windowsListeningPorts()[os.Getpid()] {
		if got == port {
			found = true
		}
	}
	if !found {
		t.Fatalf("listener %d missing from TCP ownership table", port)
	}
	targets := discoverTargets("", "openssl", os.Getpid(), 0, "custom-ssl.dll")
	if len(targets) != 1 || targets[0].Service != "openssl" || targets[0].Library != "custom-ssl.dll" {
		t.Fatalf("generic OpenSSL discovery: %+v", targets)
	}
}

func TestWindowsNginxCoverageWithoutProbeHelpers(t *testing.T) {
	previousIIS, previousOpenSSL := iisProbe, opensslProbe
	iisProbe, opensslProbe = "", ""
	t.Cleanup(func() { iisProbe, opensslProbe = previousIIS, previousOpenSSL })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &Store{stats: session.Stats{TLSCoverage: "unverified"}}
	captureWindowsServices(ctx, s, nil, func() []session.Target {
		return []session.Target{
			{ID: "1:nginx", Service: "nginx", State: "https-unverified"},
			{ID: "2:apache", Service: "apache", State: "https-unverified"},
		}
	})

	if s.stats.TLS != "unavailable" || s.stats.TLSCoverage != "unavailable" {
		t.Fatalf("TLS=%q, coverage=%q", s.stats.TLS, s.stats.TLSCoverage)
	}
	if s.stats.GapCounts["windows-probe/probe_unavailable/attempts"] != 1 {
		t.Fatalf("expected one nginx availability gap, got %v", s.stats.GapCounts)
	}
	targets := s.stats.Targets
	if len(targets) != 2 || targets[0].State != "unavailable" || targets[1].State != "https-unverified" {
		t.Fatalf("unexpected target states: %+v", targets)
	}
}
