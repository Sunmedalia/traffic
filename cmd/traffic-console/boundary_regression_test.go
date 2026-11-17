package main

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExternalReanalysisPublishesConsistentProvenance(t *testing.T) {
	s := tuiTestStore(t)
	putTUITransaction(t, s, Transaction{ID: "x", Time: time.Now(), URL: "/local-marker", Method: "GET"})
	os.WriteFile(filepath.Join(s.dir, "capture.lock"), nil, 0600)
	rs, _ := rulesFromYAML(nil)
	_, err := analyzeSessionRules(context.Background(), s.dir, "", rs, time.Minute, 20)
	if err != nil {
		t.Fatal(err)
	}
	web := newWebServer([]string{s.dir}, "audit-test-token", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	path := "/api/sessions/" + webSessionID(s.dir)
	ruleRequest(t, server, web.token, "GET", path+"/requests", nil)
	rs, _ = validateRuleContent(testManagedRules)
	second, err := analyzeSessionRules(context.Background(), s.dir, "", rs, time.Minute, 20)
	if err != nil {
		t.Fatal(err)
	}
	_, raw := ruleRequest(t, server, web.token, "GET", path+"/requests?alerts=1", nil)
	var response struct {
		Count int   `json:"count"`
		Stats Stats `json:"stats"`
	}
	json.Unmarshal(raw, &response)
	code, archive := ruleRequest(t, server, web.token, "GET", path+"/requests/x/export", nil)
	if code != 200 {
		t.Fatalf("export %d %s", code, archive)
	}
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	var metadata analysisReport
	var event Transaction
	for _, f := range z.File {
		r, _ := f.Open()
		b, _ := io.ReadAll(r)
		r.Close()
		if f.Name == "analysis.json" {
			json.Unmarshal(b, &metadata)
		}
		if f.Name == "event.json" {
			json.Unmarshal(b, &event)
		}
	}
	if response.Count != 1 || response.Stats.Alerts != second.Alerts || metadata.RulesSHA256 != second.RulesSHA256 || len(event.Alerts) != 1 {
		t.Fatalf("not reproduced: %+v %+v %+v", response, metadata, event)
	}
	t.Log("fresh API reads and export metadata belong to the same published generation")
}
func TestAnalysisRejectsSessionSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix symlink probe")
	}
	s := tuiTestStore(t)
	putTUITransaction(t, s, Transaction{ID: "x", Time: time.Now(), URL: "/.env"})
	outside := filepath.Join(t.TempDir(), "unrelated.sqlite")
	external, err := sql.Open("sqlite3", outside)
	if err != nil {
		t.Fatal(err)
	}
	_, err = external.Exec("CREATE TABLE private_data(id INTEGER)")
	if err != nil {
		t.Fatal(err)
	}
	external.Close()
	if err = os.Symlink(outside, filepath.Join(s.dir, "analysis.sqlite")); err != nil {
		t.Fatal(err)
	}
	rs, _ := rulesFromYAML(nil)
	_, err = analyzeSessionRules(context.Background(), s.dir, "", rs, time.Minute, 20)
	if err == nil {
		t.Fatal("analysis followed session symlink")
	}
	external, err = sql.Open("sqlite3", outside)
	if err != nil {
		t.Fatal(err)
	}
	defer external.Close()
	var count int
	if err = external.QueryRow("SELECT count(*) FROM metadata").Scan(&count); err == nil {
		t.Fatal("external database was modified", count)
	}
	t.Log("session symlink rejected without changing the external database")
}
func TestSlowCancelDoesNotBlockJobControl(t *testing.T) {
	web := newWebServer([]string{t.TempDir()}, "audit-test-token", time.Second)
	defer web.close()
	ctx, cancel := context.WithCancel(web.ctx)
	defer cancel()
	_ = ctx
	web.job = &webAnalysisJob{ID: "x", State: "running"}
	web.jobCancel = cancel
	server := httptest.NewServer(web.handler())
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "DELETE /api/analysis HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{", web.token)
	request, _ := http.NewRequest("GET", server.URL+"/api/analysis", nil)
	request.Header.Set("Authorization", "Bearer "+web.token)
	client := &http.Client{Timeout: 150 * time.Millisecond}
	response, err := client.Do(request)
	if response != nil {
		response.Body.Close()
	}
	conn.Close()
	if err != nil {
		t.Fatal("slow request blocked task status", err)
	}
	t.Log("task status remains responsive while cancellation body is incomplete")
}
