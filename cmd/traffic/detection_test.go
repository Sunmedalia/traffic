package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestExpandedDetection(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ rule, field, payload string }{
		{"XSS-001", "request", "<img src=x onerror=alert(1)>"},
		{"SSRF-001", "request", "url=http://169.254.169.254/latest/meta-data/"},
		{"XXE-001", "request", `<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]>`},
		{"SSTI-001", "request", "{{7*7}}"},
		{"JNDI-001", "request", "${jndi:ldap://example.test/a}"},
		{"DESERIAL-001", "request", "rO0ABXNy"},
		{"WEBSHELL-UPLOAD-001", "request", "Content-Disposition: form-data; name=upload; filename=\"shell.php\""},
		{"WEBSHELL-ACCESS-001", "url", "/shell.php?cmd=id"},
		{"RESPONSE-PASSWD-001", "response", "root:x:0:0:root:/root:/bin/bash\n"},
		{"RESPONSE-CMD-001", "response", "uid=0(root) gid=0(root) groups=0(root)"},
	} {
		t.Run(test.rule, func(t *testing.T) {
			record := Transaction{}
			raw := []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s", len(test.payload), test.payload))
			switch test.field {
			case "url":
				record.URL = test.payload
			case "response":
				record.Response = []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(test.payload), test.payload))
			default:
				record.Request = raw
			}
			for _, alert := range detect(record) {
				if alert.Rule == test.rule {
					return
				}
			}
			t.Fatalf("missing %s", test.rule)
		})
	}
}

func TestDetectionFieldIsolation(t *testing.T) {
	original := rules
	defer func() { rules = original }()
	for _, field := range []string{"request.headers", "request.header.X-Probe", "request.body", "response.headers", "response.header.X-Probe", "response.body"} {
		t.Run(field, func(t *testing.T) {
			rules = []Rule{{ID: "CUSTOM", Version: 1, Severity: "high", Field: field, Pattern: "needle"}}
			if err := compileRules(rules); err != nil {
				t.Fatal(err)
			}
			for _, location := range []string{"request.headers", "request.body", "response.headers", "response.body"} {
				requestHead, requestBody, responseHead, responseBody := "", "", "", ""
				switch location {
				case "request.headers":
					requestHead = "X-Probe: needle\r\n"
				case "request.body":
					requestBody = "needle"
				case "response.headers":
					responseHead = "X-Probe: needle\r\n"
				case "response.body":
					responseBody = "needle"
				}
				record := Transaction{
					Request:  []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\n%sContent-Length: %d\r\n\r\n%s", requestHead, len(requestBody), requestBody)),
					Response: []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n%s", responseHead, len(responseBody), responseBody)),
				}
				want := field == location || strings.Replace(field, ".header.X-Probe", ".headers", 1) == location
				if got := len(detect(record)) > 0; got != want {
					t.Errorf("%s in %s = %v, want %v", field, location, got, want)
				}
			}
		})
	}
	for _, field := range []string{"response.header.", "request.header.bad name", "response.bad"} {
		if validRuleField(field) {
			t.Errorf("accepted invalid field %s", field)
		}
	}
}

func TestCompressedResponseDetectionAndUpdate(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	p.process(strings.NewReader("GET / HTTP/1.1\r\nHost: test\r\n\r\n"), "pair", "192.0.2.1:1234", "test", 1, false)
	var body bytes.Buffer
	writer := gzip.NewWriter(&body)
	writer.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
	writer.Close()
	raw := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", body.Len())), body.Bytes()...)
	p.process(bytes.NewReader(raw), "pair", "192.0.2.1:1234", "test", 1, false)
	var data []byte
	if err := s.db.QueryRow("SELECT data FROM requests").Scan(&data); err != nil {
		t.Fatal(err)
	}
	var record Transaction
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	for _, alert := range record.Alerts {
		if alert.Rule == "RESPONSE-PASSWD-001" && alert.View == "gzip-body" {
			return
		}
	}
	t.Fatalf("response evidence missing %+v", record.Alerts)
}

func TestTrustedProxyResolution(t *testing.T) {
	original := trustedProxies
	defer func() { trustedProxies = original }()
	var err error
	trustedProxies, err = parseTrustedProxies("10.0.0.0/8,2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, peer, headers, want, source string }{
		{"untrusted", "192.0.2.1:80", "X-Forwarded-For: 198.51.100.1\r\n", "192.0.2.1:80", ""},
		{"chain", "10.1.1.1:80", "X-Forwarded-For: 198.51.100.1, 10.2.2.2\r\n", "198.51.100.1:0", "x-forwarded-for"},
		{"spoofed left", "10.1.1.1:80", "X-Forwarded-For: 203.0.113.9, 198.51.100.1\r\n", "198.51.100.1:0", "x-forwarded-for"},
		{"repeated", "10.1.1.1:80", "X-Forwarded-For: 198.51.100.1\r\nX-Forwarded-For: 10.2.2.2\r\n", "198.51.100.1:0", "x-forwarded-for"},
		{"real", "10.1.1.1:80", "X-Real-IP: 198.51.100.1\r\n", "198.51.100.1:0", "x-real-ip"},
		{"ipv6", "[2001:db8::1]:80", "X-Forwarded-For: 2001:db9::2\r\n", "[2001:db9::2]:0", "x-forwarded-for"},
		{"malformed", "10.1.1.1:80", "X-Forwarded-For: unknown\r\nX-Real-IP: 198.51.100.1\r\n", "10.1.1.1:80", ""},
		{"empty", "10.1.1.1:80", "X-Forwarded-For: \r\n", "10.1.1.1:80", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := Transaction{Client: test.peer, Request: []byte("GET / HTTP/1.1\r\nHost: test\r\n" + test.headers + "\r\n")}
			resolveClient(&record)
			if record.Client != test.want || record.ClientSource != test.source {
				t.Fatalf("got %+v", record)
			}
			resolveClient(&record)
			if record.Client != test.want {
				t.Fatalf("repeat resolution changed identity %+v", record)
			}
			if test.source != "" && record.PeerClient != test.peer {
				t.Fatal("transport address missing")
			}
		})
	}
	if _, err := parseTrustedProxies("10.0.0.0/8,typo"); err == nil {
		t.Fatal("invalid config accepted")
	}
}

func TestProxyIdentityPersistsOnResponse(t *testing.T) {
	original := trustedProxies
	defer func() { trustedProxies = original }()
	trustedProxies, _ = parseTrustedProxies("10.0.0.0/8")
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	record := Transaction{ID: "proxy", Time: time.Now(), Client: "10.1.1.1:1234", Request: []byte("GET / HTTP/1.1\r\nHost: test\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n")}
	if err := s.save(record); err != nil {
		t.Fatal(err)
	}
	if err := s.restore(&record); err != nil {
		t.Fatal(err)
	}
	record.Response = []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if err := s.save(record); err != nil {
		t.Fatal(err)
	}
	if err := s.restore(&record); err != nil {
		t.Fatal(err)
	}
	if record.Client != "198.51.100.1:0" || record.PeerClient != "10.1.1.1:1234" {
		t.Fatalf("bad identity %+v", record)
	}
}

func TestTLSWireDiagnostics(t *testing.T) {
	s := &Store{}
	p := newHTTP(s)
	p.process(bytes.NewReader([]byte{22, 3, 3, 0, 2, 1, 0, 23, 3, 3, 0, 1, 42, 23, 3, 3, 0, 2, 1}), "wire", "peer", "pcap:test", 0, false)
	if s.stats.TLSWireRecords != 2 {
		t.Fatalf("complete record count %d", s.stats.TLSWireRecords)
	}
	if s.stats.TLSMissingEstimate != nil {
		t.Fatal("unknown loss must not become zero")
	}
}

func TestNamedHeadersDoNotReadBody(t *testing.T) {
	original := rules
	defer func() { rules = original }()
	for _, field := range []string{"request.header.body", "response.header.body", "request.header.headers", "response.header.headers"} {
		rules = []Rule{{ID: "CUSTOM", Version: 1, Severity: "high", Field: field, Pattern: "needle"}}
		if err := compileRules(rules); err != nil {
			t.Fatal(err)
		}
		record := Transaction{Request: []byte("POST / HTTP/1.1\r\nHost: needle\r\nContent-Length: 6\r\n\r\nneedle"), Response: []byte("HTTP/1.1 200 OK\r\nX-Probe: needle\r\nContent-Length: 6\r\n\r\nneedle")}
		if len(detect(record)) != 0 {
			t.Fatalf("field %s leaked into body or other headers", field)
		}
	}
	rules = []Rule{{ID: "HOST", Version: 1, Severity: "high", Field: "request.header.Host", Pattern: "needle"}}
	if err := compileRules(rules); err != nil {
		t.Fatal(err)
	}
	if len(detect(Transaction{Request: []byte("GET / HTTP/1.1\r\nHost: needle\r\n\r\n")})) != 1 {
		t.Fatal("Host header was lost")
	}
}

func TestRepeatedHeaderAndLFDetection(t *testing.T) {
	original := rules
	defer func() { rules = original }()
	rules = []Rule{{ID: "CUSTOM", Version: 1, Severity: "high", Field: "request.header.X-Probe", Pattern: "needle"}}
	if err := compileRules(rules); err != nil {
		t.Fatal(err)
	}
	record := Transaction{Request: []byte("GET / HTTP/1.1\nHost: test\nX-Probe: safe\nX-Probe: needle\n\n")}
	if len(detect(record)) != 1 {
		t.Fatal("repeated header values missing")
	}
	rules[0].Field = "request.headers"
	if err := compileRules(rules); err != nil {
		t.Fatal(err)
	}
	if len(detect(record)) != 1 {
		t.Fatal("LF headers missing")
	}
}
