package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOpenAnalysisBuildPragmas(t *testing.T) {
	dir := t.TempDir()
	build, err := createAnalysisBuild(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openAnalysisBuild(filepath.Join(dir, build))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var cacheSize int
	if err := db.QueryRow("PRAGMA cache_size").Scan(&cacheSize); err != nil || cacheSize != -65536 {
		t.Fatalf("cache_size = %d (err=%v), want -65536", cacheSize, err)
	}
	var tempStore int
	if err := db.QueryRow("PRAGMA temp_store").Scan(&tempStore); err != nil || tempStore != 2 {
		t.Fatalf("temp_store = %d (err=%v), want 2 (MEMORY)", tempStore, err)
	}
	var lockingMode string
	if err := db.QueryRow("PRAGMA locking_mode").Scan(&lockingMode); err != nil || !strings.EqualFold(lockingMode, "exclusive") {
		t.Fatalf("locking_mode = %q (err=%v), want exclusive", lockingMode, err)
	}
}

func TestDetectionMessagePlanReuseAndDecodePercent(t *testing.T) {
	// Empty raw input short-circuits.
	if got := detectionMessageWith(nil, false, 1024, allMessageNeeds, nil); got.raw != "" || got.headers != "" || got.body != "" || got.decoded != "" || got.decodedView != "" || got.fields != nil {
		t.Fatalf("empty raw returned %+v", got)
	}

	// Field plan skips unreferenced fields while still decoding gzip body with reused bufio.Reader.
	rs := []Rule{{ID: "R-BODY", Version: 1, Severity: "high", Field: "response.body", Pattern: "secret-token"}}
	if err := compileRules(rs); err != nil {
		t.Fatal(err)
	}
	plan := planRuleFields(rs)
	if plan.response.raw || plan.response.headers || plan.response.fields || !plan.response.body || !plan.response.decoded {
		t.Fatalf("unexpected response plan: %+v", plan.response)
	}

	br := bufio.NewReaderSize(nil, 4096)
	payload := gzipped("hello secret-token world")
	raw := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload))
	for range 4 {
		msg := detectionMessageWith(raw, true, 1024, plan.response, br)
		if msg.raw != "" || msg.headers != "" || msg.fields != nil {
			t.Fatalf("unreferenced fields were populated: raw=%q headers=%q fields=%v", msg.raw, msg.headers, msg.fields)
		}
		if msg.decodedView != "gzip-body" || !strings.Contains(msg.decoded, "secret-token") {
			t.Fatalf("gzip body not decoded: view=%q decoded=%q", msg.decodedView, msg.decoded)
		}
	}

	// decodePercent fast path and malformed escapes.
	for _, tc := range []struct {
		in, want string
	}{
		{"plain-ascii-123", "plain-ascii-123"},
		{"a+b%20c%2Fd", "a b c/d"},
		{"bad%zz+ok%20tail%", "bad%zz ok tail%"},
		{"%2", "%2"},
		{"%41%42%GG%43", "AB%GGC"},
	} {
		if got := decodePercent(tc.in); got != tc.want {
			t.Fatalf("decodePercent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAnalyzeWebhookReadsFromEntries(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	putTUITransaction(t, writer, Transaction{
		ID:      "atk-1",
		Time:    now,
		Client:  "198.51.100.7:54321",
		Method:  "GET",
		Host:    "demo",
		URL:     "/search?q=1%20union%20select%202",
		Status:  200,
		Request: []byte("GET /search?q=1%20union%20select%202 HTTP/1.1\r\nHost: demo\r\n\r\n"),
	})
	if err := os.WriteFile(filepath.Join(writer.dir, "status.json"), []byte(`{"state":"stopped","transactions":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(writer.dir, "capture.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var received []map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			mu.Lock()
			received = append(received, m)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer hook.Close()

	rs, err := rulesFromYAML(nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := analyzeSessionRules(context.Background(), writer.dir, hook.URL, rs, time.Minute, 20)
	if err != nil {
		t.Fatal(err)
	}
	if report.Delivery == nil || report.Delivery.AlertDelivered < 1 {
		t.Fatalf("expected webhook delivery, got %+v", report.Delivery)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 || received[0]["id"] != "atk-1" || received[0]["client"] != "198.51.100.7:54321" || received[0]["url"] != "/search?q=1%20union%20select%202" {
		t.Fatalf("unexpected webhook payload: %+v", received)
	}
}

func TestWebTimelineCacheAndStrictBearerAuth(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC()
	putTUITransaction(t, writer, Transaction{ID: "t1", Time: now, Client: "192.0.2.1:1000", Method: "GET", Host: "demo", URL: "/"})
	if err := os.WriteFile(filepath.Join(writer.dir, "status.json"), []byte(`{"state":"stopped","transactions":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	web := newWebServer([]string{writer.dir}, "secret-token-phase2-0123456789", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()

	// Authorization header without "Bearer " prefix must be rejected even if token matches.
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/sessions", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", web.token)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bare token without Bearer prefix got %d, want 401", resp.StatusCode)
	}

	// Timeline caches finished sessions and invalidates when session changes.
	sid := webSessionID(writer.dir)
	timelinePath := "/api/sessions/" + sid + "/timeline"
	status, body, _ := webGet(t, server, web.token, timelinePath)
	var tl sessionTimeline
	if status != http.StatusOK || json.Unmarshal(body, &tl) != nil || tl.Total != 1 {
		t.Fatalf("first timeline: %d %s", status, body)
	}
	web.timelineMu.Lock()
	cachedCount := len(web.timelines)
	web.timelineMu.Unlock()
	if cachedCount != 1 {
		t.Fatalf("expected timeline cache to hold 1 entry, got %d", cachedCount)
	}
	// Second request hits cache.
	status, body, _ = webGet(t, server, web.token, timelinePath)
	if status != http.StatusOK || json.Unmarshal(body, &tl) != nil || tl.Total != 1 {
		t.Fatalf("cached timeline: %d %s", status, body)
	}
	// Adding a transaction invalidates the cache.
	putTUITransaction(t, writer, Transaction{ID: "t2", Time: now.Add(time.Second), Client: "192.0.2.2:1000", Method: "GET", Host: "demo", URL: "/2"})
	status, body, _ = webGet(t, server, web.token, timelinePath)
	if status != http.StatusOK || json.Unmarshal(body, &tl) != nil || tl.Total != 2 {
		t.Fatalf("invalidated timeline: %d %s", status, body)
	}
}

func TestCompileRulesLimitsAndLightweightRuleRevision(t *testing.T) {
	tooMany := make([]Rule, maxCompiledRules+1)
	for i := range tooMany {
		tooMany[i] = Rule{ID: fmt.Sprintf("R-%d", i), Version: 1, Severity: "low", Field: "url", Pattern: "abc"}
	}
	if err := compileRules(tooMany); err == nil || !strings.Contains(err.Error(), "too many rules") {
		t.Fatalf("expected too many rules error, got %v", err)
	}

	tooLong := []Rule{{ID: "R-LONG", Version: 1, Severity: "low", Field: "url", Pattern: strings.Repeat("a", maxRulePatternLength+1)}}
	if err := compileRules(tooLong); err == nil || !strings.Contains(err.Error(), "pattern too long") {
		t.Fatalf("expected pattern too long error, got %v", err)
	}

	// Lightweight revision check allows deleting an invalid YAML file by its SHA-256 revision.
	lib, err := openRuleLibrary(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer lib.root.Close()
	invalidYAML := []byte("not: [valid: yaml")
	if err := os.WriteFile(filepath.Join(lib.dir, "broken.yaml"), invalidYAML, 0600); err != nil {
		t.Fatal(err)
	}
	rev, err := lib.readRevision("broken.yaml")
	if err != nil || rev != ruleRevision(invalidYAML) {
		t.Fatalf("readRevision = %q (err=%v), want %q", rev, err, ruleRevision(invalidYAML))
	}

	validYAML := "- id: CUSTOM-1\n  version: 1\n  severity: medium\n  field: url\n  pattern: /admin\n"
	saved, status, err := lib.write("custom.yaml", validYAML, "")
	if err != nil || status != http.StatusOK || !saved.Valid || saved.Count != 1 || saved.Revision != ruleRevision([]byte(validYAML)) {
		t.Fatalf("write failed: status=%d err=%v file=%+v", status, err, saved)
	}
	if _, status, err := lib.write("custom.yaml", validYAML, "wrong-rev"); err == nil || status != http.StatusConflict {
		t.Fatalf("expected conflict on stale revision, got status=%d err=%v", status, err)
	}
}

func TestExportContextCancelAndSemaphoreLimit(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC()
	putTUITransaction(t, writer, Transaction{ID: "exp-1", Time: now, Client: "192.0.2.1:1000", Method: "GET", Host: "demo", URL: "/"})
	if err := os.WriteFile(filepath.Join(writer.dir, "status.json"), []byte(`{"state":"stopped","transactions":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(writer.dir, "capture.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	// Canceled context aborts exportEvidenceContext without leaving a zip file.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := filepath.Join(t.TempDir(), "cancelled.zip")
	if err := exportEvidenceContext(ctx, writer, Transaction{ID: "exp-1", Time: now}, []byte(`{"id":"exp-1"}`), out); err == nil {
		t.Fatalf("expected cancellation error")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("cancelled export left file behind: %v", err)
	}

	// Saturated semaphore returns 429 Too Many Requests.
	web := newWebServer([]string{writer.dir}, "export-sem-token-0123456789", time.Second)
	defer web.close()
	for range cap(web.exportSem) {
		web.exportSem <- struct{}{}
	}
	defer func() {
		for range cap(web.exportSem) {
			<-web.exportSem
		}
	}()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	sid := webSessionID(writer.dir)
	status, body, _ := webGet(t, server, web.token, "/api/sessions/"+sid+"/requests/exp-1/export")
	if status != http.StatusTooManyRequests {
		t.Fatalf("saturated export got %d (%s), want 429", status, body)
	}
	if !bytes.Contains(body, []byte("导出任务过多")) {
		t.Fatalf("unexpected 429 body: %s", body)
	}
}
