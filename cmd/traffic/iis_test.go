package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

func TestIISRequestResponseAndLoss(t *testing.T) {
	store, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	assembler := &iisAssembler{store: store, target: session.Target{ID: "worker", Service: "iis"}}
	events := []iisEvent{
		{Type: "request", ID: "one", Time: time.Now(), Method: "POST", URL: "/api/echo", Local: "127.0.0.1:8443", Headers: [][2]string{{"Host", "test"}, {"Content-Length", "6"}}},
		{Type: "request-body", ID: "one", Data: []byte("中文"), Length: 6},
		{Type: "response", ID: "one", Status: 200, Headers: [][2]string{{"Transfer-Encoding", "chunked"}}},
		{Type: "response-body", ID: "one", Data: []byte("2\r\nok\r\n0\r\n\r\n"), Length: 12},
		{Type: "response-end", ID: "one"},
	}
	for _, event := range events {
		if err := assembler.ingest(event); err != nil {
			t.Fatal(err)
		}
	}
	var data []byte
	if err := store.db.QueryRow("SELECT data FROM requests").Scan(&data); err != nil {
		t.Fatal(err)
	}
	var record Transaction
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.Incomplete || record.Status != 200 || record.Backend != "iis-httpapi" || !bytes.Contains(record.Request, []byte("中文")) || !bytes.HasSuffix(record.Response, []byte("ok")) || bytes.Contains(record.Response, []byte("chunked")) {
		t.Fatalf("invalid IIS reconstruction %+v", record)
	}
	events[0].ID = "two"
	if err := assembler.ingest(events[0]); err != nil {
		t.Fatal(err)
	}
	if err := assembler.ingest(iisEvent{Type: "loss", Count: 1}); err != nil {
		t.Fatal(err)
	}
	if err := assembler.finish(); err != nil {
		t.Fatal(err)
	}
	rows, err := store.db.Query("SELECT data FROM requests WHERE id != ?", record.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("missing interrupted request")
	}
	if err := rows.Scan(&data); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if !record.Incomplete || store.stats.TLSDropped != 1 {
		t.Fatalf("lost IIS gap: %+v", record)
	}
}

func TestIISChunkedBodyLimit(t *testing.T) {
	originalLimit := responseLimit
	responseLimit = 4
	t.Cleanup(func() { responseLimit = originalLimit })
	store, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	assembler := &iisAssembler{store: store, target: session.Target{ID: "worker", Service: "iis"}}
	events := []iisEvent{
		{Type: "request", ID: "one", Time: time.Now(), Method: "GET", URL: "/chunked"},
		{Type: "request-end", ID: "one"},
		{Type: "response", ID: "one", Status: 200, Headers: [][2]string{{"Transfer-Encoding", "chunked"}}},
		{Type: "response-body", ID: "one", Data: []byte("a\r\nhello"), Length: 8},
		{Type: "response-body", ID: "one", Data: []byte("world\r\n0\r\n\r\n"), Length: 12},
		{Type: "response-end", ID: "one"},
	}
	for _, event := range events {
		if err := assembler.ingest(event); err != nil {
			t.Fatal(err)
		}
	}
	var data []byte
	if err := store.db.QueryRow("SELECT data FROM requests").Scan(&data); err != nil {
		t.Fatal(err)
	}
	var record Transaction
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if !record.Truncated || record.Incomplete || !bytes.HasSuffix(record.Response, []byte("\r\n\r\nhell")) {
		t.Fatalf("chunk framing counted as body bytes: %+v", record)
	}
}
