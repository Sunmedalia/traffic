package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

func TestLocalAnalysisPreservesEvidenceAndSupportsReanalysis(t *testing.T) {
	writer := tuiTestStore(t)
	stamp := time.Now().UTC()
	request := []byte("GET /?q=union%20select%201 HTTP/1.1\r\nHost: test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nroot:x:0:0:")
	putTUITransaction(t, writer, Transaction{ID: "attack", Time: stamp, Client: "192.0.2.1:1234", Method: "GET", URL: "/?q=union%20select%201", Status: 200, Request: request, Response: response})
	for i := 19; i >= 0; i-- {
		putTUITransaction(t, writer, Transaction{ID: fmt.Sprint(i), Time: stamp.Add(time.Duration(i+1) * time.Millisecond), Client: "192.0.2.2:1234", URL: fmt.Sprintf("/scan/%d", i), Status: 404})
	}
	if err := writer.db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"capture.lock": "", "manifest.json": `{"detection_mode":"offline"}`, "status.json": `{"state":"stopped","alerts":0}`} {
		if err := os.WriteFile(filepath.Join(writer.dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(filepath.Join(writer.dir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err = loadRules(""); err != nil {
		t.Fatal(err)
	}
	scanWindow, scanThreshold = time.Minute, 20
	report, err := analyzeSession(context.Background(), writer.dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if report.Transactions != 21 || report.Alerts != 3 {
		t.Fatalf("unexpected report %+v", report)
	}
	// A cancelled rebuild never replaces the last published generation.
	publishedPath, err := analysisDatabasePath(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	published, err := os.ReadFile(publishedPath)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err = analyzeSession(cancelled, writer.dir, ""); err == nil {
		t.Fatal("cancelled rebuild succeeded")
	}
	retainedPath, err := analysisDatabasePath(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(retainedPath)
	if err != nil || !bytes.Equal(published, retained) {
		t.Fatal("failed rebuild replaced published results", err)
	}
	reader, err := openStore(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.db.Close()
	var raw []byte
	var record Transaction
	if err = reader.db.QueryRow("SELECT data FROM records WHERE id='attack'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Alerts) != 2 || string(record.Request) != string(request) || string(record.Response) != string(response) {
		t.Fatalf("bad analyzed event %+v", record)
	}
	snapshot, err := loadTUISnapshot(context.Background(), reader, tuiFilter{Rule: "SQLI-001"}, true, 0, "attack", nil)
	if err != nil || snapshot.Count != 1 || snapshot.Stats.Alerts != 3 {
		t.Fatalf("analysis not visible in UI: %+v %v", snapshot, err)
	}
	web := newWebServer([]string{writer.dir}, "local-analysis-test", time.Second)
	server := httptest.NewServer(web.handler())
	code, body, _ := webGet(t, server, web.token, "/api/sessions")
	var sessions struct {
		Sessions []webSession `json:"sessions"`
	}
	if err = json.Unmarshal(body, &sessions); err != nil || code != http.StatusOK || len(sessions.Sessions) != 1 || sessions.Sessions[0].Alerts != 3 {
		t.Fatalf("web session missing analysis: %d %s", code, body)
	}
	code, body, _ = webGet(t, server, web.token, "/api/sessions/"+sessions.Sessions[0].ID+"/requests?alerts=1&rule=SQLI-001")
	var list struct {
		Count int `json:"count"`
	}
	if err = json.Unmarshal(body, &list); err != nil || code != http.StatusOK || list.Count != 1 {
		t.Fatalf("web filter missing analysis: %d %s", code, body)
	}
	server.Close()
	web.close()
	if _, err = reader.db.Exec("DELETE FROM main.requests"); err == nil {
		t.Fatal("analysis can alter evidence")
	}
	if _, err = reader.db.Exec("DELETE FROM analysis.results"); err == nil {
		t.Fatal("viewer can alter analysis")
	}
	archive := filepath.Join(t.TempDir(), "evidence.zip")
	if err = exportEvidence(reader, record, raw, archive); err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	files := map[string]bool{}
	for _, f := range z.File {
		files[f.Name] = true
	}
	if !files["analysis.json"] || !files["captured-event.json"] {
		t.Fatal("export lost provenance", files)
	}
	reader.db.Close()
	custom := filepath.Join(t.TempDir(), "rules.yaml")
	if err = os.WriteFile(custom, []byte("- id: CUSTOM\n  version: 1\n  severity: low\n  field: url\n  pattern: union\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"analyze", "--session", writer.dir, "--rules", custom}); err != nil {
		t.Fatal(err)
	}
	customReport, err := readAnalysisReport(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	if customReport.Alerts != 4 || customReport.RulesSHA256 == report.RulesSHA256 {
		t.Fatalf("custom rules not applied %+v", customReport)
	}
	if err = run([]string{"analyze", "--session", writer.dir}); err != nil {
		t.Fatal(err)
	}
	if current, err := readAnalysisReport(writer.dir); err != nil || current.Alerts != 3 || current.RulesSHA256 != report.RulesSHA256 {
		t.Fatal("reanalysis retained old rules or alerts", current, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = analyzeSession(ctx, writer.dir, ""); err == nil {
		t.Fatal("cancelled analysis succeeded")
	}
	if current, err := readAnalysisReport(writer.dir); err != nil || current.Alerts != 3 {
		t.Fatal("failed analysis replaced previous results", current, err)
	}
	after, err := os.ReadFile(filepath.Join(writer.dir, "index.sqlite"))
	if err != nil || string(before) != string(after) {
		t.Fatal("analysis rewrote original index", err)
	}
	status, _ := os.ReadFile(filepath.Join(writer.dir, "status.json"))
	if string(status) != `{"state":"stopped","alerts":0}` {
		t.Fatal("analysis rewrote capture status")
	}
}

func TestReanalysisReplacesLegacyAlertsWithEmptyResults(t *testing.T) {
	writer := tuiTestStore(t)
	putTUITransaction(t, writer, Transaction{ID: "legacy", Time: time.Now(), URL: "/normal", Alerts: []Alert{{Rule: "OLD-RULE", Severity: "high"}}})
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	report, err := analyzeSession(context.Background(), writer.dir, "")
	if err != nil || report.Alerts != 0 {
		t.Fatal("legacy alerts retained in new analysis", report, err)
	}
	reader, err := openStore(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.db.Close()
	var count int
	if err = reader.db.QueryRow("SELECT count(*) FROM records WHERE alert>0").Scan(&count); err != nil || count != 0 {
		t.Fatal("legacy alerts visible after reanalysis", count, err)
	}
	var raw []byte
	if err = reader.db.QueryRow("SELECT data FROM main.requests WHERE id='legacy'").Scan(&raw); err != nil || !strings.Contains(string(raw), "OLD-RULE") {
		t.Fatal("legacy evidence changed", err)
	}
}

func TestAnalysisRejectsActiveCaptureAndInvalidatesChangedEvidence(t *testing.T) {
	writer := tuiTestStore(t)
	putTUITransaction(t, writer, Transaction{ID: "a", Time: time.Now(), URL: "/.env"})
	lock, err := os.OpenFile(filepath.Join(writer.dir, "capture.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = session.LockFile(lock, true); err != nil {
		t.Fatal(err)
	}
	if _, err = analyzeSession(context.Background(), writer.dir, ""); err == nil || !strings.Contains(err.Error(), "stop capture") {
		t.Fatal("accepted active capture", err)
	}
	session.UnlockFile(lock)
	if err = loadRules(""); err != nil {
		t.Fatal(err)
	}
	if _, err = analyzeSession(context.Background(), writer.dir, ""); err != nil {
		t.Fatal(err)
	}
	putTUITransaction(t, writer, Transaction{ID: "b", Time: time.Now(), URL: "/normal"})
	reader, err := openStore(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.db.Close()
	if reader.analysis != nil || !strings.Contains(reader.analysisNote, "重新运行") {
		t.Fatal("stale analysis silently reused", reader.analysisNote)
	}
	if err = run([]string{"events", "--session", writer.dir, "--rules", "missing.yaml"}); err == nil {
		t.Fatal("query accepted unused analysis rules")
	}
}
