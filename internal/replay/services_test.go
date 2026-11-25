package replay

import (
	"github.com/Sunmedalia/traffic/internal/session"
	"testing"
	"time"
)

func TestPlainHTTPAttributionRequiresLocalAddress(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	s.stats.Targets = []session.Target{{Service: "apache", Ports: []int{80}}}
	for _, sample := range []struct{ id, endpoint, want string }{{"local", "127.0.0.1:80", "apache"}, {"remote", "203.0.113.20:80", ""}} {
		record := Transaction{ID: sample.id, Time: time.Now(), LocalEndpoint: sample.endpoint, URL: "/"}
		if err = s.save(record); err != nil {
			t.Fatal(err)
		}
		if err = s.restore(&record); err != nil {
			t.Fatal(err)
		}
		if record.Service != sample.want {
			t.Fatalf("%s attributed to %q", sample.endpoint, record.Service)
		}
	}
}

func TestJavaEventGapIsPreserved(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	frames := &Frames{}
	frames.ingest("read", []byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"), frameContext{connection: "java:target:1", client: "127.0.0.1:1000", incomplete: true, local: "127.0.0.1:8443"}, false, p)
	record, ok := storedRecords(t, s)["/"]
	if !ok || !record.Incomplete || record.LocalEndpoint != "127.0.0.1:8443" || s.stats.TLSDropped != 0 {
		t.Fatalf("lost gap metadata: %+v %+v", record, s.stats)
	}
}
