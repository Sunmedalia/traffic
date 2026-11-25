package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
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

	"github.com/Sunmedalia/traffic/internal/index"
)

func TestQuerySessionSummaryBoundsAndClientHosts(t *testing.T) {
	db, err := sql.Open(index.Driver, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(entriesTable + ";" + entriesIndexes); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC).Format(indexTimeFormat)
	rows := []struct {
		id, client string
		alert, sev int
		alerts     string
	}{
		{"1", "192.0.2.1:4000", 1, 3, `[{"rule":"R-HIGH","severity":"high"}]`},
		{"2", "192.0.2.1:5000", 0, 0, `[]`},
		{"3", "192.0.2.2", 1, 99, `[{"rule":"R-OOB-HI","severity":"high"}]`},
		{"4", "[2001:db8::1]:4000", 1, -1, `[{"rule":"R-OOB-LO","severity":"low"}]`},
		{"5", "2001:db8::1", 0, 0, `[]`},
		{"6", "::1", 1, 2, `[{"rule":"R-MED","severity":"medium"}]`},
		{"7", "[::1]:8080", 0, 0, `[]`},
		{"8", "unknown", 1, 1, `[{"rule":"R-LOW","severity":"low"}]`},
	}
	for _, r := range rows {
		if _, err := db.Exec(
			`INSERT INTO entries(id,time,client,alert,severity,rule,alerts,method,host,url,status,service,incomplete,truncated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.id, now, r.client, r.alert, r.sev, "", r.alerts, "GET", "demo", "/", 200, "", 0, 0,
		); err != nil {
			t.Fatal(err)
		}
	}

	summary, err := querySessionSummary(context.Background(), db, tuiFilter{})
	if err != nil {
		t.Fatalf("querySessionSummary failed: %v", err)
	}
	clients := map[string]webCount{}
	for _, c := range summary.Clients {
		clients[c.Name] = c
	}
	wantClients := map[string]webCount{
		"192.0.2.1":   {Name: "192.0.2.1", Count: 2, Alerts: 1},
		"192.0.2.2":   {Name: "192.0.2.2", Count: 1, Alerts: 1},
		"2001:db8::1": {Name: "2001:db8::1", Count: 2, Alerts: 1},
		"::1":         {Name: "::1", Count: 2, Alerts: 1},
		"unknown":     {Name: "unknown", Count: 1, Alerts: 1},
	}
	if len(clients) != len(wantClients) {
		t.Fatalf("clients = %+v, want %+v", summary.Clients, wantClients)
	}
	for name, want := range wantClients {
		if got := clients[name]; got != want {
			t.Fatalf("client %q = %+v, want %+v", name, got, want)
		}
	}

	sevs := map[string]int{}
	for _, s := range summary.Severities {
		sevs[s.Name] += s.Count
	}
	if sevs["high"] != 1 || sevs["medium"] != 1 || sevs["low"] != 1 || sevs[""] != 2 {
		t.Fatalf("severities = %+v, want high:1 medium:1 low:1 empty:2", summary.Severities)
	}
}

func TestScanUpdatesExistingPathAtCap(t *testing.T) {
	scanner := &scanTracker{clients: map[string]*scanState{}}
	base := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	for i := range maxScanPaths {
		scanWithState(Transaction{
			Time:   base,
			Client: "10.0.0.1:1234",
			URL:    fmt.Sprintf("/p/%d", i),
			Status: 200,
		}, scanner, time.Hour, 20)
	}
	if scanner.skipped.Paths != 0 || len(scanner.clients["10.0.0.1"].paths) != maxScanPaths {
		t.Fatalf("setup unexpected: skipped=%+v paths=%d", scanner.skipped, len(scanner.clients["10.0.0.1"].paths))
	}

	// Updating an existing path at maxScanPaths must succeed without counting as skipped.
	later := base.Add(10 * time.Second)
	scanWithState(Transaction{
		Time:   later,
		Client: "10.0.0.1:1234",
		URL:    "/p/0?q=1",
		Status: 404,
	}, scanner, time.Hour, 20)
	st := scanner.clients["10.0.0.1"]
	if scanner.skipped.Paths != 0 {
		t.Fatalf("existing path at cap was skipped: %+v", scanner.skipped)
	}
	if got := st.paths["/p/0"]; got.status != 404 || !got.when.Equal(later) {
		t.Fatalf("existing path not updated: %+v", got)
	}
	if st.missing != 1 {
		t.Fatalf("missing = %d, want 1", st.missing)
	}

	// A genuinely new path at maxScanPaths must still be skipped.
	scanWithState(Transaction{
		Time:   later,
		Client: "10.0.0.1:1234",
		URL:    "/p/new",
		Status: 404,
	}, scanner, time.Hour, 20)
	if scanner.skipped.Paths != 1 || len(st.paths) != maxScanPaths {
		t.Fatalf("new path at cap: skipped=%+v paths=%d", scanner.skipped, len(st.paths))
	}
}

func TestFilterWhereUsesAlertPartialIndex(t *testing.T) {
	db, err := sql.Open(index.Driver, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(entriesTable + ";" + entriesIndexes); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		filter tuiFilter
	}{
		{"rule", tuiFilter{Rule: "SQLI-001"}},
		{"severity", tuiFilter{Severity: "high"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			where, args := tc.filter.where(false)
			if !strings.Contains(where, "alert>0") {
				t.Fatalf("where clause missing alert>0: %s", where)
			}
			rows, err := db.Query("EXPLAIN QUERY PLAN SELECT id FROM entries WHERE "+where+" ORDER BY time DESC,id DESC LIMIT 10", args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan []string
			for rows.Next() {
				var id, parent, notused int
				var detail string
				if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			joined := strings.Join(plan, "\n")
			if !strings.Contains(joined, "entries_alert_time") {
				t.Fatalf("query plan did not use entries_alert_time:\n%s", joined)
			}
		})
	}
}

func TestRecordsSelectShortCircuitsEmptyAlerts(t *testing.T) {
	db, err := sql.Open(index.Driver, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE requests(id TEXT PRIMARY KEY,time TEXT,client TEXT,alert INTEGER,data BLOB);` + entriesTable + `;CREATE VIEW records AS ` + recordsSelect("requests", "entries")); err != nil {
		t.Fatal(err)
	}

	// Extra whitespace would be stripped if json_set ran; preserving exact bytes proves short-circuit.
	rawNoAlert := []byte(`{  "id" : "no-alert" , "method" : "GET"  }`)
	rawHadAlert := []byte(`{"id":"cleared","alerts":[{"rule":"OLD","severity":"low"}]}`)
	rawNewAlert := []byte(`{"id":"added","method":"GET"}`)
	for _, r := range []struct {
		id     string
		alert  int
		data   []byte
		alerts string
	}{
		{"no-alert", 0, rawNoAlert, `[]`},
		{"cleared", 1, rawHadAlert, `[]`},
		{"added", 0, rawNewAlert, `[{"rule":"SQLI-001","severity":"high"}]`},
	} {
		if _, err := db.Exec(`INSERT INTO requests VALUES(?,?,?,?,?)`, r.id, "2026-11-25T00:00:00.000000000Z", "192.0.2.1:1", r.alert, r.data); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.id, "2026-11-25T00:00:00.000000000Z", "192.0.2.1:1", 0, 0, "", r.alerts, "GET", "", "/", 200, "", 0, 0); err != nil {
			t.Fatal(err)
		}
	}

	var alert int
	var data []byte
	if err := db.QueryRow(`SELECT alert,data FROM records WHERE id='no-alert'`).Scan(&alert, &data); err != nil {
		t.Fatal(err)
	}
	if alert != 0 || !bytes.Equal(data, rawNoAlert) {
		t.Fatalf("no-alert was rewritten: alert=%d data=%q want=%q", alert, data, rawNoAlert)
	}

	if err := db.QueryRow(`SELECT alert,data FROM records WHERE id='cleared'`).Scan(&alert, &data); err != nil {
		t.Fatal(err)
	}
	var cleared Transaction
	if err := json.Unmarshal(data, &cleared); err != nil || alert != 0 || len(cleared.Alerts) != 0 {
		t.Fatalf("cleared alert not removed: alert=%d tx=%+v err=%v", alert, cleared, err)
	}

	if err := db.QueryRow(`SELECT alert,data FROM records WHERE id='added'`).Scan(&alert, &data); err != nil {
		t.Fatal(err)
	}
	var added Transaction
	if err := json.Unmarshal(data, &added); err != nil || alert != 1 || len(added.Alerts) != 1 || added.Alerts[0].Rule != "SQLI-001" {
		t.Fatalf("added alert not merged: alert=%d tx=%+v err=%v", alert, added, err)
	}
}

func TestStoreCacheLRUAndRevisionInvalidation(t *testing.T) {
	makeSession := func() (*Store, string) {
		w := tuiTestStore(t)
		putTUITransaction(t, w, Transaction{ID: "1", Time: time.Now().UTC(), Client: "192.0.2.1:1", Method: "GET", URL: "/"})
		if err := os.WriteFile(filepath.Join(w.dir, "status.json"), []byte(`{"state":"stopped","transactions":1}`), 0600); err != nil {
			t.Fatal(err)
		}
		return w, w.dir
	}
	_, dir1 := makeSession()
	w2, dir2 := makeSession()
	_, dir3 := makeSession()

	cache := newStoreCache(2)
	defer cache.close()

	s1a, rel1a, err := cache.acquire(dir1)
	if err != nil {
		t.Fatal(err)
	}
	s1b, rel1b, err := cache.acquire(dir1)
	if err != nil {
		t.Fatal(err)
	}
	if s1a != s1b {
		t.Fatalf("expected cache hit for same (dir, revision)")
	}
	rel1b()

	// Keep s1a leased while filling and evicting dir1 from the 2-entry LRU.
	s2, rel2, err := cache.acquire(dir2)
	if err != nil {
		t.Fatal(err)
	}
	rel2()
	s3, rel3, err := cache.acquire(dir3)
	if err != nil {
		t.Fatal(err)
	}
	rel3()
	_ = s3

	// s1a was evicted from LRU, but must remain usable until its lease is released.
	var count int
	if err := s1a.db.QueryRow("SELECT count(*) FROM entries").Scan(&count); err != nil || count != 1 {
		t.Fatalf("leased evicted store failed: count=%d err=%v", count, err)
	}
	rel1a()
	if err := s1a.db.QueryRow("SELECT count(*) FROM entries").Scan(&count); err == nil {
		t.Fatalf("evicted store db was not closed after final release")
	}

	// Mutating dir2 changes its revision and yields a fresh *Store.
	putTUITransaction(t, w2, Transaction{ID: "2", Time: time.Now().UTC().Add(time.Second), Client: "192.0.2.2:1", Method: "GET", URL: "/2"})
	s2New, rel2New, err := cache.acquire(dir2)
	if err != nil {
		t.Fatal(err)
	}
	defer rel2New()
	if s2New == s2 {
		t.Fatalf("expected new *Store after revision change")
	}
	if err := s2New.db.QueryRow("SELECT count(*) FROM entries").Scan(&count); err != nil || count != 2 {
		t.Fatalf("updated store count=%d err=%v", count, err)
	}
}

func TestLoadTUISnapshotAndSummaryReuseOpenStore(t *testing.T) {
	db, err := sql.Open(index.Driver, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE requests(id TEXT PRIMARY KEY,time TEXT,client TEXT,alert INTEGER,data BLOB);` + entriesTable + `;CREATE VIEW records AS ` + recordsSelect("requests", "entries")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(indexTimeFormat)
	if _, err := db.Exec(`INSERT INTO entries VALUES('a',?,'192.0.2.1:1',1,3,'SQLI-001','[{"rule":"SQLI-001","severity":"high","match":"union"}]','GET','demo','/a',200,'',0,0)`, now); err != nil {
		t.Fatal(err)
	}
	// Non-existent dir guarantees openStore(s.dir) would fail if called.
	s := &Store{db: db, dir: filepath.Join(t.TempDir(), "does-not-exist"), reader: true}

	snap, err := loadTUISnapshot(context.Background(), s, tuiFilter{}, false, 0, "", nil)
	if err != nil || snap.Count != 1 {
		t.Fatalf("loadTUISnapshot did not reuse open store: snap=%+v err=%v", snap, err)
	}
	sum, err := loadTUISummary(context.Background(), s, tuiFilter{})
	if err != nil || sum.AlertRequests != 1 {
		t.Fatalf("loadTUISummary did not reuse open store: sum=%+v err=%v", sum, err)
	}
}

func TestGzipThresholdAndPoolReuse(t *testing.T) {
	serve := func(body []byte, setLength bool) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		gw := &gzipResponseWriter{ResponseWriter: rec}
		gw.Header().Set("Content-Type", "application/json")
		if setLength {
			gw.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		}
		gw.WriteHeader(http.StatusOK)
		// Write in chunks to exercise buffering across multiple Write calls.
		for i := 0; i < len(body); i += 300 {
			end := min(i+300, len(body))
			if _, err := gw.Write(body[i:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
		return rec
	}

	small := bytes.Repeat([]byte("a"), gzipMinBytes-1)
	for _, setLength := range []bool{false, true} {
		rec := serve(small, setLength)
		if rec.Header().Get("Content-Encoding") != "" {
			t.Fatalf("small body (setLength=%v) should skip gzip, got %q", setLength, rec.Header().Get("Content-Encoding"))
		}
		if !bytes.Equal(rec.Body.Bytes(), small) {
			t.Fatalf("small body mismatch (setLength=%v)", setLength)
		}
	}

	large := bytes.Repeat([]byte("b"), gzipMinBytes*2)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := serve(large, false)
			if rec.Header().Get("Content-Encoding") != "gzip" {
				t.Errorf("large body was not gzipped: %q", rec.Header().Get("Content-Encoding"))
				return
			}
			gr, err := gzip.NewReader(rec.Body)
			if err != nil {
				t.Errorf("gzip reader: %v", err)
				return
			}
			got, err := io.ReadAll(gr)
			gr.Close()
			if err != nil || !bytes.Equal(got, large) {
				t.Errorf("gunzip mismatch: err=%v len=%d", err, len(got))
			}
		}()
	}
	wg.Wait()
}
