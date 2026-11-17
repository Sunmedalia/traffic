package replay

import (
	"bytes"
	"testing"
	"time"
)

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
