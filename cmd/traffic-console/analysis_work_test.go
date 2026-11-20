package main

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/Sunmedalia/traffic/internal/replay"
	"github.com/Sunmedalia/traffic/internal/session"
)

func workTestSession(t *testing.T, requests int, body int) string {
	t.Helper()
	now := time.Now().UTC()
	target := &session.Target{PID: 7, ID: "7:start", Service: "nginx", Ports: []int{443}}
	events := []session.RawEvent{{Version: 1, Time: now, Source: "a", Type: "source", Backend: "ecapture", Target: target}}
	payload := strings.Repeat("x", body)
	for i := 0; i < requests; i++ {
		connection := fmt.Sprint("c", i)
		request := fmt.Sprintf("POST /r%d HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s", i, len(payload), payload)
		events = append(events,
			session.RawEvent{Version: 1, Time: now, Source: "a", Type: "data", Connection: connection, Direction: "read", Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Data: []byte(request)},
			session.RawEvent{Version: 1, Time: now, Source: "a", Type: "data", Connection: connection, Direction: "write", Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")})
	}
	return rawTestSession(t, events)
}

func analyzeWorkTest(t *testing.T, dir string) (analysisReport, error) {
	t.Helper()
	rs, err := rulesFromYAML(nil)
	if err != nil {
		t.Fatal(err)
	}
	return analyzeSessionRules(context.Background(), dir, "", rs, time.Minute, 20)
}

func analysisBuilds(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".analysis-build-*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

// The rebuilt index lives on the session's filesystem, not $TMPDIR.
func TestAnalysisDoesNotNeedTMPDIR(t *testing.T) {
	dir := workTestSession(t, 3, 16)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	report, err := analyzeWorkTest(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Transactions != 3 {
		t.Fatal("transactions", report.Transactions)
	}
	if left := analysisBuilds(t, dir); len(left) != 0 {
		t.Fatal("build left behind", left)
	}
	if _, err := readAnalysisReport(dir); err != nil {
		t.Fatal(err)
	}
}

// A full disk used to surface only as the follow-up commit error
// ("cannot commit - no transaction is active").
func TestFullAnalysisDiskReportsCause(t *testing.T) {
	dir := workTestSession(t, 200, 8<<10)
	db, err := sql.Open(index.Driver, analysisURL(filepath.Join(t.TempDir(), "analysis.sqlite"), "rwc"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA max_page_count=64"); err != nil {
		t.Fatal(err)
	}
	_, err = replay.Build(context.Background(), dir, db, replay.Options{RequestLimit: requestLimit, ResponseLimit: responseLimit})
	if err == nil || !diskFull(err) || strings.Contains(err.Error(), "no transaction is active") {
		t.Fatal("disk-full cause not reported", err)
	}
}

func TestExportStampsMemberTimes(t *testing.T) {
	s := tuiTestStore(t)
	if err := os.WriteFile(filepath.Join(s.dir, "capture.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "event.zip")
	transaction := Transaction{ID: "example", Time: time.Now(), Request: []byte("example")}
	raw, err := json.Marshal(transaction)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-2 * time.Second)
	if err = exportEvidence(s, transaction, raw, out); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	for _, member := range archive.File {
		if member.Modified.Before(before) {
			t.Fatalf("%s modified %v", member.Name, member.Modified)
		}
		if member.Name == "request.http" {
			reader, err := member.Open()
			if err != nil {
				t.Fatal(err)
			}
			var data bytes.Buffer
			_, _ = data.ReadFrom(reader)
			reader.Close()
			if data.String() != "example" {
				t.Fatal("member content", data.String())
			}
		}
	}
}
