package main

import (
	"bytes"
	"testing"
)

func TestCapturePreservesSuspiciousTrafficWithoutDetection(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	request := []byte("GET /?q=union%20select%201 HTTP/1.1\r\nHost: test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nroot:x:0:0:")
	p.process(bytes.NewReader(request), "capture-only", "192.0.2.1:1234", "test", 0, false)
	p.process(bytes.NewReader(response), "capture-only", "192.0.2.1:1234", "test", 0, false)
	var id string
	if err = s.db.QueryRow("SELECT id FROM requests").Scan(&id); err != nil {
		t.Fatal(err)
	}
	record := Transaction{ID: id}
	if err = s.restore(&record); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.Request, request) || !bytes.Equal(record.Response, response) || len(record.Alerts) != 0 || s.stats.Alerts != 0 {
		t.Fatalf("capture changed evidence or ran detection: %+v", record)
	}
	for _, args := range [][]string{{"rules", "check", "test.yaml"}, {"capture", "--rules", "test.yaml"}, {"capture", "--alert-webhook", "https://example.invalid"}} {
		if err = run(args); err == nil {
			t.Fatalf("collector accepted analysis option %v", args)
		}
	}
}
