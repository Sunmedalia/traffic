package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func webGet(t *testing.T, server *httptest.Server, token, path string) (int, []byte, http.Header) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body, response.Header
}

func TestWebServesSessionsOverTokenProtectedAPI(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC()
	putTUITransaction(t, writer, Transaction{ID: "a/1", Time: now, Client: "192.0.2.1:4000", Method: "GET", Host: "demo", URL: "/?q=<script>", Status: 200,
		Request: []byte("GET /?q=<script> HTTP/1.1\r\nHost: demo\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\n\xff"), Alerts: []Alert{{Rule: "RULE-A", Severity: "high", Match: "<script>"}}})
	putTUITransaction(t, writer, Transaction{ID: "b", Time: now.Add(-time.Minute), Client: "192.0.2.2:4000", Method: "POST", Host: "other", URL: "/plain"})
	if err := os.WriteFile(filepath.Join(writer.dir, "status.json"), []byte(`{"state":"stopped","transactions":2,"alerts":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(writer.dir, "capture.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	web := newWebServer([]string{writer.dir}, "secret-token-0123456789", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	token := web.token

	for _, bad := range []string{"", "wrong"} {
		if status, _, _ := webGet(t, server, bad, "/api/sessions"); status != http.StatusUnauthorized {
			t.Fatalf("token %q got status %d", bad, status)
		}
	}
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range webScripts {
		if !strings.Contains(string(index), `<script src="`+name+`"></script>`) {
			t.Fatalf("index.html does not load %s", name)
		}
	}
	for path, want := range map[string]string{"/": "main.js", "/app.js": "use strict", "/decoder.js": "DECODERS", "/rules.js": "use strict", "/analysis.js": "use strict", "/main.js": "boot();", "/app.css": "--bg"} {
		status, body, header := webGet(t, server, "", path)
		if status != http.StatusOK || !strings.Contains(string(body), want) || !strings.Contains(header.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatalf("asset %s status %d", path, status)
		}
		if path != "/" && header.Get("Cache-Control") != "no-cache" {
			t.Fatalf("asset %s cache control %q", path, header.Get("Cache-Control"))
		}
	}
	status, _, header := webGet(t, server, "", "/app.js")
	etag := header.Get("ETag")
	if status != http.StatusOK || etag == "" {
		t.Fatalf("asset etag %d %q", status, etag)
	}
	conditional, err := http.NewRequest(http.MethodGet, server.URL+"/app.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	conditional.Header.Set("If-None-Match", etag)
	response, err := server.Client().Do(conditional)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional asset status %d", response.StatusCode)
	}
	compressed, err := http.NewRequest(http.MethodGet, server.URL+"/app.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	compressed.Header.Set("Accept-Encoding", "gzip")
	response, err = server.Client().Do(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Content-Encoding") != "gzip" {
		response.Body.Close()
		t.Fatalf("asset was not compressed: %q", response.Header.Get("Content-Encoding"))
	}
	gz, err := gzip.NewReader(response.Body)
	if err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(gz)
	response.Body.Close()
	if err != nil || !bytes.Contains(decoded, []byte("use strict")) {
		t.Fatalf("compressed asset %v", err)
	}
	if status, _, _ := webGet(t, server, "", "/index.sqlite"); status != http.StatusNotFound {
		t.Fatalf("unexpected file status %d", status)
	}

	var sessions struct {
		Sessions []webSession `json:"sessions"`
	}
	status, body, apiHeader := webGet(t, server, token, "/api/sessions")
	if apiHeader.Get("Cache-Control") != "no-store" {
		t.Fatalf("api cache control %q", apiHeader.Get("Cache-Control"))
	}
	if err := json.Unmarshal(body, &sessions); err != nil || status != http.StatusOK || len(sessions.Sessions) != 1 {
		t.Fatalf("sessions %d %s", status, body)
	}
	apiCompressed, err := http.NewRequest(http.MethodGet, server.URL+"/api/sessions", nil)
	if err != nil {
		t.Fatal(err)
	}
	apiCompressed.Header.Set("Authorization", "Bearer "+token)
	apiCompressed.Header.Set("Accept-Encoding", "gzip")
	apiResponse, err := server.Client().Do(apiCompressed)
	if err != nil {
		t.Fatal(err)
	}
	if apiResponse.Header.Get("Content-Encoding") != "gzip" {
		apiResponse.Body.Close()
		t.Fatalf("api was not compressed: %q", apiResponse.Header.Get("Content-Encoding"))
	}
	apiGzip, err := gzip.NewReader(apiResponse.Body)
	if err != nil {
		apiResponse.Body.Close()
		t.Fatal(err)
	}
	apiBody, err := io.ReadAll(apiGzip)
	apiResponse.Body.Close()
	if err != nil || !bytes.Contains(apiBody, []byte(`"sessions"`)) {
		t.Fatalf("compressed api %v", err)
	}
	found := sessions.Sessions[0]
	if found.State != "stopped" || found.Transactions != 2 || found.Alerts != 1 || found.Problem != "" {
		t.Fatalf("session %+v", found)
	}
	base := "/api/sessions/" + found.ID + "/requests"

	var list struct {
		Rows     []webRow `json:"rows"`
		Count    int      `json:"count"`
		Page     int      `json:"page"`
		PageSize int      `json:"page_size"`
		Stats    Stats    `json:"stats"`
	}
	cases := map[string]int{"": 2, "?alerts=1": 1, "?severity=high&rule=RULE-A": 1, "?severity=low": 1, "?severity=medium&rule=RULE-B": 0, "?keyword=plain": 1, "?client=192.0.2.2": 1,
		"?since=" + url.QueryEscape(now.Add(-time.Second).Format(time.RFC3339Nano)): 1}
	for query, want := range cases {
		status, body, _ = webGet(t, server, token, base+query)
		list.Rows = nil
		if err := json.Unmarshal(body, &list); err != nil || status != http.StatusOK || list.Count != want || len(list.Rows) != want {
			t.Fatalf("query %q: status %d body %s", query, status, body)
		}
	}
	for query, want := range map[string]int{"?status=2xx": 1, "?status=200": 1, "?status=pending": 1, "?status=4xx": 0, "?method=POST": 1, "?method=PUT": 0,
		"?until=" + url.QueryEscape(now.Add(-time.Second).Format(time.RFC3339Nano)): 1} {
		status, body, _ = webGet(t, server, token, base+query)
		list.Rows = nil
		if err := json.Unmarshal(body, &list); err != nil || status != http.StatusOK || list.Count != want || len(list.Rows) != want {
			t.Fatalf("web filter %q: status %d body %s", query, status, body)
		}
	}
	status, body, _ = webGet(t, server, token, base+"?limit=1")
	list.Rows = nil
	if err := json.Unmarshal(body, &list); err != nil || status != http.StatusOK || list.Count != 2 || len(list.Rows) != 1 || list.PageSize != 1 || list.Page != 0 {
		t.Fatalf("limit page: status %d body %s", status, body)
	}
	for _, query := range []string{"?severity=critical", "?since=yesterday", "?until=tomorrow", "?status=9xx", "?status=ok", "?status=42", "?limit=0", "?limit=501"} {
		if status, _, _ = webGet(t, server, token, base+query); status != http.StatusBadRequest {
			t.Fatalf("query %q got status %d", query, status)
		}
	}
	if status, _, _ = webGet(t, server, token, "/api/sessions/ffffffffffffffff/requests"); status != http.StatusNotFound {
		t.Fatalf("unknown session status %d", status)
	}

	var timeline struct {
		Total       int         `json:"total"`
		Granularity int         `json:"granularity"`
		Buckets     []webBucket `json:"buckets"`
	}
	sessionBase := "/api/sessions/" + found.ID
	status, body, _ = webGet(t, server, token, sessionBase+"/timeline")
	if err := json.Unmarshal(body, &timeline); err != nil || status != http.StatusOK {
		t.Fatalf("timeline %d %s", status, body)
	}
	requests, alerts := 0, 0
	for _, bucket := range timeline.Buckets {
		if _, err := time.Parse(time.RFC3339, bucket.Time); err != nil {
			t.Fatalf("bucket time %q: %v", bucket.Time, err)
		}
		requests, alerts = requests+bucket.Requests, alerts+bucket.Alerts
	}
	if timeline.Total != 2 || timeline.Granularity != 1 || len(timeline.Buckets) != 2 || requests != 2 || alerts != 1 {
		t.Fatalf("timeline %+v", timeline)
	}
	status, body, _ = webGet(t, server, token, sessionBase+"/timeline?alerts=1&keyword=plain")
	if err := json.Unmarshal(body, &timeline); err != nil || status != http.StatusOK || timeline.Total != 0 || len(timeline.Buckets) != 0 {
		t.Fatalf("empty timeline %d %s", status, body)
	}
	if status, _, _ = webGet(t, server, token, sessionBase+"/timeline?status=nope"); status != http.StatusBadRequest {
		t.Fatalf("timeline accepted an invalid filter: %d", status)
	}

	var summary struct {
		Total      int        `json:"total"`
		Alerted    int        `json:"alerted"`
		Clients    []webCount `json:"clients"`
		Rules      []webCount `json:"rules"`
		Severities []webCount `json:"severities"`
		Statuses   []webCount `json:"statuses"`
	}
	status, body, _ = webGet(t, server, token, sessionBase+"/summary")
	if err := json.Unmarshal(body, &summary); err != nil || status != http.StatusOK {
		t.Fatalf("summary %d %s", status, body)
	}
	if summary.Total != 2 || summary.Alerted != 1 || len(summary.Clients) != 2 || summary.Clients[0] != (webCount{Name: "192.0.2.1", Count: 1, Alerts: 1}) {
		t.Fatalf("summary clients %+v", summary)
	}
	if len(summary.Rules) != 1 || summary.Rules[0] != (webCount{Name: "RULE-A", Severity: "high", Count: 1}) || len(summary.Severities) != 1 || summary.Severities[0].Name != "high" {
		t.Fatalf("summary alerts %+v", summary)
	}
	if len(summary.Statuses) != 2 || summary.Statuses[0] != (webCount{Name: "pending", Count: 1}) || summary.Statuses[1] != (webCount{Name: "2xx", Count: 1}) {
		t.Fatalf("summary statuses %+v", summary.Statuses)
	}

	var detail struct {
		Transaction  map[string]any `json:"transaction"`
		RequestText  string         `json:"request_text"`
		ResponseText string         `json:"response_text"`
	}
	status, body, _ = webGet(t, server, token, base+"/"+url.PathEscape("a/1"))
	if err := json.Unmarshal(body, &detail); err != nil || status != http.StatusOK {
		t.Fatalf("detail %d %s", status, body)
	}
	if !strings.HasPrefix(detail.RequestText, "GET /?q=<script>") || !strings.HasSuffix(detail.ResponseText, "�") || detail.Transaction["request"] != nil || detail.Transaction["id"] != "a/1" {
		t.Fatalf("detail %+v", detail)
	}
	if status, _, _ = webGet(t, server, token, base+"/missing"); status != http.StatusNotFound {
		t.Fatalf("missing detail status %d", status)
	}
	var meta struct {
		Status     int  `json:"status"`
		Incomplete bool `json:"incomplete"`
		Truncated  bool `json:"truncated"`
		AlertCount int  `json:"alert_count"`
	}
	status, body, _ = webGet(t, server, token, base+"/"+url.PathEscape("a/1")+"/meta")
	if err := json.Unmarshal(body, &meta); err != nil || status != http.StatusOK || meta.Status != 200 || meta.AlertCount != 1 {
		t.Fatalf("meta: status %d body %s", status, body)
	}
	if status, _, _ = webGet(t, server, token, base+"/missing/meta"); status != http.StatusNotFound {
		t.Fatalf("missing meta status %d", status)
	}

	status, body, header = webGet(t, server, token, base+"/"+url.PathEscape("a/1")+"/export")
	if status != http.StatusOK || header.Get("Content-Disposition") != `attachment; filename="evidence-a1.zip"` {
		t.Fatalf("export %d %s %q", status, body, header.Get("Content-Disposition"))
	}
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, file := range archive.File {
		names[file.Name] = true
	}
	for _, name := range []string{"event.json", "request.http", "response.http", "evidence.json", "sha256.json"} {
		if !names[name] {
			t.Fatalf("export lacks %s: %v", name, names)
		}
	}
}

func TestWebListenRequiresLoopbackByDefault(t *testing.T) {
	for address, want := range map[string]bool{"127.0.0.1:8080": true, "[::1]:8080": true, "localhost:0": true, ":8080": false, "0.0.0.0:8080": false, "192.0.2.1:80": false} {
		if webLoopback(address) != want {
			t.Fatalf("loopback(%q) != %t", address, want)
		}
	}
	if err := runWeb("", t.TempDir(), t.TempDir(), "0.0.0.0:0", false, time.Second); err == nil || !strings.Contains(err.Error(), "--allow-remote") {
		t.Fatalf("remote listen was not refused: %v", err)
	}
}

func TestWebSummaryCacheInvalidates(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC()
	putTUITransaction(t, writer, Transaction{ID: "first", Time: now, Client: "192.0.2.1:1", Method: "GET", Host: "demo", URL: "/"})
	if err := os.WriteFile(filepath.Join(writer.dir, "status.json"), []byte(`{"state":"stopped","transactions":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	web := newWebServer([]string{writer.dir}, "{{SECRET_9kq2wvxz}}", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	sessions := discoverSessions(context.Background(), []string{writer.dir})
	if len(sessions.Entries) != 1 {
		t.Fatalf("sessions: %+v", sessions)
	}
	base := "/api/sessions/" + webSessionID(writer.dir) + "/summary"
	var summary struct {
		Total int `json:"total"`
	}
	status, body, _ := webGet(t, server, web.token, base)
	if err := json.Unmarshal(body, &summary); err != nil || status != http.StatusOK || summary.Total != 1 {
		t.Fatalf("first summary: %d %s", status, body)
	}
	putTUITransaction(t, writer, Transaction{ID: "second", Time: now.Add(time.Second), Client: "192.0.2.2:1", Method: "GET", Host: "demo", URL: "/"})
	status, body, _ = webGet(t, server, web.token, base)
	if err := json.Unmarshal(body, &summary); err != nil || status != http.StatusOK || summary.Total != 2 {
		t.Fatalf("summary cache did not invalidate: %d %s", status, body)
	}
}
