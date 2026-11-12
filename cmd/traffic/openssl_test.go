package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOpenSSLConnectionBoundaries(t *testing.T) {
	store, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	p := newHTTP(store)
	a := &opensslAssembler{processor: p, frames: &Frames{}, prefix: "openssl-test/"}
	send := func(kind, direction, data string) {
		t.Helper()
		if err := a.ingest(opensslEvent{Type: kind, Connection: "one", Direction: direction, Local: "127.0.0.1:443", Client: "127.0.0.1:50000", Data: []byte(data)}); err != nil {
			t.Fatal(err)
		}
	}
	// A response from a request that preceded attachment cannot match a later GET.
	send("data", "write", "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")
	send("data", "read", "GET /first HTTP/1.1\r\nHost: test\r\n\r\n")
	send("data", "write", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	send("data", "read", "POST /interrupted HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\r\n")
	if err := a.ingest(opensslEvent{Type: "loss", Count: 2}); err != nil {
		t.Fatal(err)
	}
	send("data", "write", "HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n")
	send("data", "read", "GET /after-loss HTTP/1.1\r\nHost: test\r\n\r\n")
	send("data", "write", "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	send("close", "", "")
	rows, err := store.db.Query("SELECT data FROM requests")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	records := map[string]Transaction{}
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			t.Fatal(err)
		}
		var record Transaction
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		records[record.URL] = record
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 || records["/first"].Status != 200 || records["/first"].Incomplete || !records["/interrupted"].Incomplete || records["/interrupted"].Status != 0 || records["/after-loss"].Status != 201 || !records["/after-loss"].Incomplete {
		t.Fatalf("lost stream boundaries: %+v", records)
	}
	if store.stats.TLSDropped < 2 || len(p.pending) != 0 || len(p.responses) != 0 {
		t.Fatalf("missing loss accounting or stale correlation")
	}
}

func TestConcurrentHEADResponseFraming(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	store, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	p := newHTTP(store)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// HEAD announces a body length but sends no body. The following GET response
		// must remain a separate response even if this stream runs before requests.
		p.process(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno"), "head-race", "client", "test", 0, false)
	}()
	time.Sleep(10 * time.Millisecond)
	p.process(strings.NewReader("HEAD /head HTTP/1.1\r\nHost: test\r\n\r\nGET /following HTTP/1.1\r\nHost: test\r\n\r\n"), "head-race", "client", "test", 0, false)
	<-done
	var data []byte
	rows, err := store.db.Query("SELECT data FROM requests")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		if err := rows.Scan(&data); err != nil {
			t.Fatal(err)
		}
		var record Transaction
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		if record.Incomplete || (record.Method == "HEAD" && record.Status != 200) || (record.Method == "GET" && record.Status != 404) {
			t.Fatalf("response framing: %+v", record)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("got %d records", count)
	}
}

func TestTruncatedBodyKeepsFollowingResponse(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	previous := responseLimit
	responseLimit = 4
	defer func() { responseLimit = previous }()
	store, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	p := newHTTP(store)
	p.process(strings.NewReader("GET /large HTTP/1.1\r\nHost: test\r\n\r\nGET /next HTTP/1.1\r\nHost: test\r\n\r\n"), "truncated", "client", "test", 0, false)
	p.process(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n12345678HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"), "truncated", "client", "test", 0, false)
	rows, err := store.db.Query("SELECT data FROM requests")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			t.Fatal(err)
		}
		var record Transaction
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		if record.URL == "/next" {
			found = true
			if record.Status != 201 || record.Incomplete || record.Truncated {
				t.Fatalf("following response lost: %+v", record)
			}
		}
	}
	if !found {
		t.Fatal("missing following request")
	}
}
