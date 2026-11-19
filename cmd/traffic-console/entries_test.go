package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
)

// legacyEntriesSession writes a stopped v1 index whose transactions exercise
// every column the entries layout stores.
func legacyEntriesSession(t testing.TB, count, bodySize int) string {
	t.Helper()
	writer := tuiTestStore(t)
	stamp := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	methods := []string{"GET", "POST", "PUT"}
	body := []byte(strings.Repeat("b", bodySize))
	tx, err := writer.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		url := fmt.Sprintf("/item/%d?id=%d", i, i)
		switch {
		case i%7 == 0:
			url = fmt.Sprintf("/q?id=%d%%20union%%20select", i)
		case i%5 == 0:
			url = fmt.Sprintf("/static/app%d.js", i)
		case i%11 == 0:
			url = fmt.Sprintf("/admin/panel%d", i)
		}
		record := Transaction{ID: fmt.Sprintf("r%05d", i), Time: stamp.Add(time.Duration(i) * time.Second), Client: fmt.Sprintf("192.0.2.%d:%d", i%9, 1000+i),
			Method: methods[i%3], Host: fmt.Sprintf("h%d.test", i%4), URL: url, Status: []int{200, 404, 500, 302, 0}[i%5], Service: []string{"nginx", "iis"}[i%2],
			Incomplete: i%13 == 0, Truncated: i%17 == 0, Request: body, Response: body}
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec("INSERT INTO requests VALUES(?,?,?,0,?)", record.ID, record.Time.Format(indexTimeFormat), record.Client, data); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = writer.db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"capture.lock": "", "manifest.json": `{"detection_mode":"offline"}`, "status.json": `{"state":"stopped"}`} {
		if err := os.WriteFile(filepath.Join(writer.dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return writer.dir
}

func analyzeEntriesSession(t testing.TB, dir string) {
	t.Helper()
	rs, err := validateRuleContent(`- id: SQLI-T
  version: 1
  severity: high
  field: url
  pattern: (?i)union%20select
- id: ADMIN-T
  version: 1
  severity: medium
  field: url
  pattern: /admin/
- id: ANY-ID
  version: 1
  severity: low
  field: url
  pattern: id=[0-9]*0[^0-9]
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = analyzeSessionRules(context.Background(), dir, "", rs, time.Minute, 1000); err != nil {
		t.Fatal(err)
	}
}

// downgradeAnalysis turns the published generation into the engine 4 layout,
// which only stores alert results.
func downgradeAnalysis(t testing.TB, dir string) {
	t.Helper()
	path, err := analysisDatabasePath(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open(index.Driver, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("DROP VIEW IF EXISTS records; DROP TABLE entries"); err != nil {
		t.Fatal(err)
	}
}

type entriesObservation struct {
	Snapshots []tuiSnapshot
	Summaries []*tuiSummary
	Web       []string
}

func observeEntries(t *testing.T, dir string) entriesObservation {
	t.Helper()
	store, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if store.analysis == nil {
		t.Fatal("analysis not loaded", store.analysisNote)
	}
	filters := []tuiFilter{
		{},
		{Severity: "medium"},
		{Rule: "ANY-ID"},
		{Rule: "ADMIN-T", Severity: "high"},
		{Method: "POST", Status: "4xx"},
		{Status: "pending"},
		{Service: "iis", Keyword: "h1"},
		{Keyword: "union select", Decode: 1},
		{Exclude: "admin, static", Client: "192.0.2.3"},
		{Param: "id", HideStatic: true},
		{Since: "2026-11-01T00:01:00", Until: "2026-11-01T00:02:00", UntilExclusive: true},
	}
	var result entriesObservation
	for _, filter := range filters {
		for _, alerts := range []bool{false, true} {
			snapshot, err := loadTUISnapshot(context.Background(), store, filter, alerts, 1, "r00007", nil, 20)
			if err != nil {
				t.Fatal(filter, err)
			}
			snapshot.Stats = Stats{}
			result.Snapshots = append(result.Snapshots, snapshot)
		}
		summary, err := loadTUISummary(context.Background(), store, filter)
		if err != nil {
			t.Fatal(filter, err)
		}
		result.Summaries = append(result.Summaries, summary)
	}
	web := newWebServer([]string{filepath.Dir(dir)}, "entries-token", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	id := webSessionID(dir)
	for _, path := range []string{
		"/summary", "/summary?alerts=1&severity=low", "/timeline", "/timeline?method=GET",
		"/requests?status=5xx&page=1", "/requests?alerts=1", "/requests/r00007/meta", "/rule-hits",
	} {
		code, body, _ := webGet(t, server, web.token, "/api/sessions/"+id+path)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		result.Web = append(result.Web, path+" "+string(body))
	}
	return result
}

// Engine 5 lists and summaries must equal those computed from JSON records.
func TestEntriesMatchLegacyJSONLayout(t *testing.T) {
	dir := legacyEntriesSession(t, 300, 64)
	analyzeEntriesSession(t, dir)
	columns := observeEntries(t, dir)
	if columns.Snapshots[0].Count != 300 || columns.Snapshots[1].Count == 0 || columns.Snapshots[0].Detail == nil || len(columns.Snapshots[0].Detail.Alerts) == 0 {
		t.Fatalf("unexpected analysis view: count=%d alerts=%d", columns.Snapshots[0].Count, columns.Snapshots[1].Count)
	}
	downgradeAnalysis(t, dir)
	legacy := observeEntries(t, dir)
	for i := range columns.Snapshots {
		if !reflect.DeepEqual(columns.Snapshots[i], legacy.Snapshots[i]) {
			t.Fatalf("snapshot %d differs:\ncolumns %+v\nlegacy  %+v", i, columns.Snapshots[i], legacy.Snapshots[i])
		}
	}
	for i := range columns.Summaries {
		if !reflect.DeepEqual(columns.Summaries[i], legacy.Summaries[i]) {
			t.Fatalf("summary %d differs:\ncolumns %+v\nlegacy  %+v", i, columns.Summaries[i], legacy.Summaries[i])
		}
	}
	for i := range columns.Web {
		if columns.Web[i] != legacy.Web[i] {
			t.Fatalf("web response differs:\ncolumns %s\nlegacy  %s", columns.Web[i], legacy.Web[i])
		}
	}
}

// A store serves concurrent readers; each pooled connection carries its views.
func TestStoreServesConcurrentReaders(t *testing.T) {
	dir := legacyEntriesSession(t, 50, 16)
	for _, analyzed := range []bool{false, true} {
		if analyzed {
			analyzeEntriesSession(t, dir)
		}
		store, err := openStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		var conns []*sql.Conn
		for range storeReaders {
			conn, err := store.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var count int
			if err = conn.QueryRowContext(ctx, "SELECT count(*) FROM entries e JOIN records r USING(id)").Scan(&count); err != nil || count != 50 {
				t.Fatal("pooled connection lacks store relations", analyzed, count, err)
			}
			conns = append(conns, conn)
		}
		for _, conn := range conns {
			conn.Close()
		}
		store.db.Close()
	}
}
