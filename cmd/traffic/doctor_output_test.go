package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/Sunmedalia/traffic/internal/session"
	"github.com/google/gopacket/pcap"
)

func windowsDoctorFixture() map[string]any {
	return map[string]any{
		"os": "windows", "arch": "amd64", "administrator": true,
		"packet_backend": "windivert-sniff", "bundled_packet_driver": `C:\Users\Administrator\traffic\deps\windivert\WinDivert.dll`,
		"npcap_installed": false, "iis_installed": false, "tls_configured": true, "tls_verified": false, "tls_backend": "iis-httpapi,openssl",
		"targets": []session.Target(nil), "checks": []captureCheck{},
		"interfaces": []pcap.Interface{
			{Name: "windivert", Description: "全部本机接口及回环（随包 WinDivert）"},
			{Name: "windivert:5", Description: "Ethernet", Addresses: []pcap.InterfaceAddress{
				{IP: net.ParseIP("fe80::50f5:afaf:ec32:d917"), Netmask: net.CIDRMask(64, 128)},
				{IP: net.ParseIP("192.168.1.8"), Netmask: net.CIDRMask(24, 32)},
			}},
		},
	}
}

func TestDoctorReadableWindowsReport(t *testing.T) {
	var out bytes.Buffer
	if err := writeDoctorOutput(&out, windowsDoctorFixture(), "80,8080", false); err != nil {
		t.Fatal(err)
	}
	value := out.String()
	t.Log("\n" + value)
	for _, expected := range []string{"环境自检", "Windows / amd64 · 管理员", "[待验证] 驱动能否加载", "[无需安装] Npcap", "192.168.1.8/24", "fe80::50f5:afaf:ec32:d917/64", "[未发现] 支持的目标服务", "[待验证] HTTPS", ".\\traffic.exe capture --no-tls --ports 80,8080", "doctor --json"} {
		if !strings.Contains(value, expected) {
			t.Errorf("missing %q in report:\n%s", expected, value)
		}
	}
	for _, absent := range []string{"////AA==", "null", "[已验证]", "\x1b"} {
		if strings.Contains(value, absent) {
			t.Errorf("unexpected %q in readable report", absent)
		}
	}
	if strings.Index(value, "192.168.1.8/24") > strings.Index(value, "fe80::") {
		t.Fatal("IPv4 should precede IPv6")
	}
}

func TestDoctorJSONKeepsOriginalSchema(t *testing.T) {
	report := windowsDoctorFixture()
	var out bytes.Buffer
	if err := writeDoctorOutput(&out, report, "80,443", true); err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, out.Bytes()); err != nil {
		t.Fatal(err)
	}
	if compact.String() != string(expected) {
		t.Fatal("JSON output changed diagnostic schema or values")
	}
}

func TestDoctorLinuxTargetsAndUnavailableBackend(t *testing.T) {
	report := map[string]any{
		"os": "linux", "arch": "arm64", "root": false, "btf": false, "ecapture_installed": true,
		"targets": []session.Target{{Service: "nginx", PID: 42, ID: "nginx-42", Library: "/usr/lib/libssl.so.3"}},
		"checks":  []captureCheck{{Target: "nginx-42", Backend: "ecapture-openssl", Status: "unavailable", Reason: "CO-RE BTF is unavailable; startup-loaded preload is a separate opt-in"}},
	}
	var out bytes.Buffer
	if err := writeDoctorOutput(&out, report, "8080", false); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"[需权限]", "[不可用] 内核 BTF", "nginx · PID 42", "[不可用] nginx-42", "业务启动时加载", "sudo ./traffic capture"} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("missing %q", expected)
		}
	}
	report["checks"] = []captureCheck{{Target: "nginx-42", Backend: "ecapture-openssl", Status: "candidate", Reason: "future backend diagnostic"}}
	out.Reset()
	if err := writeDoctorOutput(&out, report, "8080", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "[待附加验证]") || !strings.Contains(out.String(), "future backend diagnostic") {
		t.Fatal("candidate must stay unverified and preserve unknown diagnostics")
	}
}

func TestDoctorEscapesTerminalControlsAndReportsWriteErrors(t *testing.T) {
	report := windowsDoctorFixture()
	report["interfaces"] = []pcap.Interface{{Name: "safe", Description: "fake\n\x1b[31mrow"}}
	var out bytes.Buffer
	if err := writeDoctorOutput(&out, report, "80", false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "fake\n") || strings.Contains(out.String(), "\x1b") {
		t.Fatal("untrusted description injected terminal controls")
	}
	for _, asJSON := range []bool{false, true} {
		if err := writeDoctorOutput(doctorFailedWriter{}, report, "80", asJSON); !errors.Is(err, errDoctorWrite) {
			t.Fatalf("write failure lost: %v", err)
		}
	}
}

var errDoctorWrite = errors.New("output unavailable")

type doctorFailedWriter struct{}

func (doctorFailedWriter) Write([]byte) (int, error) { return 0, errDoctorWrite }
