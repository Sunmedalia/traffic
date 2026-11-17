package replay

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

func TestSavedRequestKeepsProcessIdentityAfterPIDReuse(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	// The same numerical PID now names a replacement target. A restored request
	// already has the original start identity and must retain that attribution.
	s.stats.Targets = []session.Target{{PID: os.Getpid(), ID: "replacement-start", Service: "nginx", Ports: []int{443}}}
	record := Transaction{ID: "old-request", Time: time.Now(), PID: os.Getpid(), TargetID: "original-start", Service: "apache", URL: "/original", LocalEndpoint: "127.0.0.1:443", Client: "127.0.0.1:12345", Status: 200}
	if err := s.save(record); err != nil {
		t.Fatal(err)
	}
	var got Transaction
	got.ID = record.ID
	if err := s.restore(&got); err != nil {
		t.Fatal(err)
	}
	if got.TargetID != record.TargetID || got.Service != record.Service {
		t.Fatal("response reassigned old evidence", got.TargetID, got.Service)
	}
}
func TestTLSFrameCarriesVerifiedIdentityToStoredRequest(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	f := &Frames{}
	meta := frameContext{targetID: "verified-probe-start", connection: "identity-frame", client: "127.0.0.1:12345", local: "127.0.0.1:443", pid: os.Getpid()}
	f.ingest("identity-frameread", []byte("GET /identity HTTP/1.1\r\nHost: test\r\n\r\n"), meta, false, p)
	f.ingest("identity-framewrite", []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), meta, false, p)
	records := readRecords(t, s)
	record := records["/identity"]
	if record.TargetID != meta.targetID || record.Status != 200 {
		t.Fatal("verified source identity was lost", record)
	}
}

func TestSerialTLSResponseDoesNotWaitForRequestInSameQueue(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	done := make(chan struct{})
	go func() {
		p.process(capturedReader{Reader: bytes.NewReader([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")), complete: true}, "tls:serial", "client", "tls-hook", 0, false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(80 * time.Millisecond):
		<-done
		t.Fatal("TLS response blocked the event loop waiting for a request in the same queue")
	}
	p.process(capturedReader{Reader: bytes.NewReader([]byte("GET /serial HTTP/1.1\r\nHost: test\r\n\r\n")), complete: true}, "tls:serial", "client", "tls-hook", 0, false)
	record := readRecords(t, s)["/serial"]
	if record.Status != 200 || !bytes.HasSuffix(record.Response, []byte("ok")) {
		t.Fatal("response-first correlation failed", record)
	}
}
