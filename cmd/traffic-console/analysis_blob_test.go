package main

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/Sunmedalia/traffic/internal/replay"
	"github.com/Sunmedalia/traffic/internal/session"
)

// blobTestSession is a raw TLS session whose bodies carry binary bytes, so a
// lossy text or base64 round trip would show.
func blobTestSession(t *testing.T) (string, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	target := &session.Target{PID: 41, ID: "41:start", Service: "nginx", Ports: []int{443}}
	body := append([]byte("BLOB_MARKER\x00\xff\xfe"), bytes.Repeat([]byte{0, 1, 2, 0xff}, 4096)...)
	request := append([]byte(fmt.Sprintf("POST /upload?id=1 HTTP/1.1\r\nHost: example\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\x00ok\xff")
	events := []session.RawEvent{{Version: 1, Source: "s", Type: "source", Backend: "ecapture", Target: target, Time: now}}
	for i := 0; i < 3; i++ {
		connection := fmt.Sprint("c", i)
		req := request
		if i > 0 {
			req = []byte(fmt.Sprintf("GET /page/%d HTTP/1.1\r\nHost: example\r\n\r\n", i))
		}
		at := now.Add(time.Duration(i) * time.Millisecond)
		events = append(events,
			session.RawEvent{Version: 1, Source: "s", Type: "data", Connection: connection, Direction: "read", Data: req, Local: "127.0.0.1:443", Client: "192.0.2.7:1234", Time: at},
			session.RawEvent{Version: 1, Source: "s", Type: "data", Connection: connection, Direction: "write", Data: response, Local: "127.0.0.1:443", Client: "192.0.2.7:1234", Time: at})
	}
	events = append(events, session.RawEvent{Version: 1, Source: "s", Type: "end", Time: now.Add(time.Second)})
	return rawTestSession(t, events), request, response
}

func blobRules(t *testing.T, pattern string) []Rule {
	t.Helper()
	rs, err := validateRuleContent("- id: BLOB-T\n  version: 1\n  severity: high\n  field: request.body\n  pattern: " + pattern + "\n- id: PAGE-T\n  version: 1\n  severity: low\n  field: url\n  pattern: /page/\n")
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

var blobLimits = replay.Options{RequestLimit: 1 << 20, ResponseLimit: 1 << 20}

func analyzeBlob(t *testing.T, dir string, rs []Rule, limits replay.Options) analysisReport {
	t.Helper()
	report, err := analyzeConfigured(context.Background(), dir, "", rs, time.Minute, 20, limits)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func openGeneration(t *testing.T, dir string) *sql.DB {
	t.Helper()
	path, err := analysisDatabasePath(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open(index.Driver, analysisURL(path, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// storeView is everything a reader of the published analysis can see.
type storeView struct {
	Records map[string]Transaction
	Stored  map[string]Transaction
	Entries []string
}

func observeStore(t *testing.T, dir string) storeView {
	t.Helper()
	store, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if store.analysis == nil {
		t.Fatal("analysis not loaded:", store.analysisNote)
	}
	if err = checkStoreSchema(context.Background(), store.db); err != nil {
		t.Fatal(err)
	}
	view := storeView{Records: map[string]Transaction{}, Stored: map[string]Transaction{}}
	for query, into := range map[string]map[string]Transaction{"SELECT id,data FROM records": view.Records, "SELECT id,data FROM stored_records": view.Stored} {
		rows, err := store.db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id string
			var raw []byte
			if err = rows.Scan(&id, &raw); err != nil {
				t.Fatal(err)
			}
			record, err := session.DecodeTransaction(raw)
			if err != nil {
				t.Fatal(query, err)
			}
			into[id] = record
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	rows, err := store.db.Query("SELECT id,time,client,alert,severity,rule,alerts,method,host,url,status,service,incomplete,truncated FROM entries ORDER BY time,id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		values := make([]any, 14)
		pointers := make([]any, len(values))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err = rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		view.Entries = append(view.Entries, fmt.Sprint(values...))
	}
	return view
}

// sameRecords compares views ignoring IDs, which are generated per replay.
func sameRecords(t *testing.T, label string, a, b storeView) {
	t.Helper()
	normalize := func(view storeView) (out []string) {
		for _, set := range []map[string]Transaction{view.Records, view.Stored} {
			var rows []string
			for _, record := range set {
				record.ID = ""
				data, _ := json.Marshal(record)
				rows = append(rows, string(data))
			}
			out = append(out, fmt.Sprint(sortStrings(rows)))
		}
		for _, entry := range view.Entries {
			// The ID is the first field of each entry row.
			_, rest, _ := strings.Cut(entry, " ")
			out = append(out, rest)
		}
		return out
	}
	if got, want := normalize(a), normalize(b); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: views differ\n got %v\nwant %v", label, got, want)
	}
}

func sortStrings(values []string) []string {
	out := append([]string(nil), values...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestAnalysisStoresBodiesAsRawBlobs(t *testing.T) {
	dir, request, response := blobTestSession(t)
	report := analyzeBlob(t, dir, blobRules(t, "BLOB_MARKER"), blobLimits)
	if report.EngineVersion != 7 || report.ReconstructionVersion != replay.Version || report.ReconstructionReused || report.ReconstructedAt.IsZero() || report.Transactions != 3 || report.Alerts != 3 {
		t.Fatalf("report %+v", report)
	}
	db := openGeneration(t, dir)
	var data, rawRequest, rawResponse []byte
	if err := db.QueryRow("SELECT data,request_raw,response_raw FROM requests WHERE json_extract(data,'$.url')='/upload?id=1'").Scan(&data, &rawRequest, &rawResponse); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rawRequest, request) || !bytes.Equal(rawResponse, response) {
		t.Fatal("BLOB bodies differ from the evidence")
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"request", "response", "alerts"} {
		if _, ok := meta[key]; ok {
			t.Fatalf("metadata JSON carries %q", key)
		}
	}
	if len(data) > 2048 {
		t.Fatalf("metadata JSON is %d bytes", len(data))
	}
	// The published file holds no view that needs a connection function, so
	// stock SQLite clients can open every object in it.
	var views int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='view'").Scan(&views); err != nil || views != 0 {
		t.Fatal("persistent views", views, err)
	}
	view := observeStore(t, dir)
	var upload Transaction
	for _, record := range view.Records {
		if record.URL == "/upload?id=1" {
			upload = record
		}
	}
	if !bytes.Equal(upload.Request, request) || !bytes.Equal(upload.Response, response) || len(upload.Alerts) != 1 || upload.Alerts[0].Rule != "BLOB-T" {
		t.Fatalf("assembled record %+v", upload.Alerts)
	}
	stored := view.Stored[upload.ID]
	if !bytes.Equal(stored.Request, request) || len(stored.Alerts) != 0 {
		t.Fatal("stored record must carry bodies and no analysis alerts")
	}
	// Export reads both: the analysed event and the reconstructed one.
	store, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	var raw []byte
	if err = store.db.QueryRow("SELECT data FROM records WHERE id=?", upload.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "evidence.zip")
	if err = exportEvidence(store, upload, raw, out); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	files := map[string][]byte{}
	for _, file := range archive.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[file.Name], _ = io.ReadAll(reader)
		reader.Close()
	}
	var event, reconstructed Transaction
	if err = json.Unmarshal(files["event.json"], &event); err != nil || !bytes.Equal(event.Request, request) || len(event.Alerts) != 1 {
		t.Fatal("exported event.json", err)
	}
	if err = json.Unmarshal(files["reconstructed-event.json"], &reconstructed); err != nil || !bytes.Equal(reconstructed.Request, request) || !bytes.Equal(reconstructed.Response, response) || len(reconstructed.Alerts) != 0 {
		t.Fatal("exported reconstructed-event.json lost its bodies", err)
	}
	if !bytes.Equal(files["request.http"], request) || !bytes.Equal(files["response.http"], response) {
		t.Fatal("exported bodies")
	}
}

// Engine 5 and 6 generations keep bodies inside requests.data and publish a
// persistent records view. They stay readable without re-analysis, show the
// same records, and are never used as a reconstruction to reuse.
func TestEngine5And6GenerationsRemainReadable(t *testing.T) {
	for _, engine := range []int{5, 6} {
		t.Run(fmt.Sprint("engine", engine), func(t *testing.T) {
			dir, request, _ := blobTestSession(t)
			rs := blobRules(t, "BLOB_MARKER")
			analyzeBlob(t, dir, rs, blobLimits)
			current := observeStore(t, dir)
			path, err := analysisDatabasePath(dir)
			if err != nil {
				t.Fatal(err)
			}
			inlineAnalysisBodies(t, path, engine)
			report, layout, err := inspectAnalysis(dir, path)
			if err != nil || layout != layoutEntries || report.EngineVersion != engine {
				t.Fatal("legacy generation", layout, err)
			}
			legacy := observeStore(t, dir)
			if !reflect.DeepEqual(legacy, current) {
				t.Fatal("legacy generation reads differently")
			}
			found := false
			for _, record := range legacy.Stored {
				found = found || bytes.Equal(record.Request, request)
			}
			if !found {
				t.Fatal("legacy stored_records lost the request body")
			}
			// Reading never modified the legacy file.
			db := openGeneration(t, dir)
			var blob int
			if err = db.QueryRow("SELECT count(*) FROM pragma_table_info('requests') WHERE name='request_raw'").Scan(&blob); err != nil || blob != 0 {
				t.Fatal("legacy generation was rewritten", err)
			}
			db.Close()
			// A re-analysis replays instead of copying the legacy layout and
			// publishes the current layout again.
			next := analyzeBlob(t, dir, blobRules(t, "NO_SUCH_MARKER"), blobLimits)
			if next.ReconstructionReused || next.Alerts != 2 {
				t.Fatalf("re-analysis of legacy generation %+v", next)
			}
			if _, layout, err = inspectAnalysis(dir, mustAnalysisPath(t, dir)); err != nil || layout != layoutBlob {
				t.Fatal("re-analysis layout", layout, err)
			}
		})
	}
}

func mustAnalysisPath(t *testing.T, dir string) string {
	t.Helper()
	path, err := analysisDatabasePath(dir)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// A legacy v1 index keeps complete JSON records; its stored_records view is
// the raw row and analysis adds alerts without reconstructing.
func TestLegacyIndexStoredRecords(t *testing.T) {
	dir := legacyEntriesSession(t, 20, 64)
	analyzeEntriesSession(t, dir)
	view := observeStore(t, dir)
	if len(view.Records) != 20 || len(view.Stored) != 20 || len(view.Entries) != 20 {
		t.Fatal("legacy index rows", len(view.Records), len(view.Stored))
	}
	for id, record := range view.Stored {
		if len(record.Request) != 64 || len(record.Alerts) != 0 || !bytes.Equal(record.Request, view.Records[id].Request) {
			t.Fatal("legacy stored record", id)
		}
	}
	report, err := readAnalysisReport(dir)
	if err != nil || report.Reconstructed || report.ReconstructionReused || report.ReconstructionVersion != 0 {
		t.Fatalf("legacy report %+v %v", report, err)
	}
}

func copySessionEvidence(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	for _, name := range []string{"manifest.json", "status.json", "capture.lock", filepath.Join("tls", "stream.jsonl")} {
		data, err := os.ReadFile(filepath.Join(from, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(filepath.Dir(filepath.Join(to, name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(to, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return to
}

// Changing only rules or scan settings reuses the reconstruction and gives
// exactly what a full replay with the new settings gives.
func TestRuleChangeReusesReconstruction(t *testing.T) {
	dir, _, _ := blobTestSession(t)
	fresh := copySessionEvidence(t, dir)
	first := analyzeBlob(t, dir, blobRules(t, "BLOB_MARKER"), blobLimits)
	if first.ReconstructionReused {
		t.Fatal("first analysis cannot reuse")
	}
	rs := blobRules(t, "NO_SUCH_MARKER")
	second, err := analyzeConfigured(context.Background(), dir, "", rs, 2*time.Minute, 50, blobLimits)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ReconstructionReused || second.Transactions != 3 || second.Alerts != 2 || !second.ReconstructedAt.Equal(first.ReconstructedAt) || second.RulesSHA256 == first.RulesSHA256 {
		t.Fatalf("second %+v", second)
	}
	if !reflect.DeepEqual(second.Reconstruction, first.Reconstruction) {
		t.Fatal("reused reconstruction statistics differ")
	}
	full, err := analyzeConfigured(context.Background(), fresh, "", rs, 2*time.Minute, 50, blobLimits)
	if err != nil || full.ReconstructionReused {
		t.Fatal(full, err)
	}
	sameRecords(t, "reused vs full replay", observeStore(t, dir), observeStore(t, fresh))
	db := openGeneration(t, dir)
	var gaps []byte
	if err = db.QueryRow("SELECT gaps FROM reconstruction WHERE id=1").Scan(&gaps); err != nil || len(gaps) == 0 {
		t.Fatal("reconstruction metadata not copied", err)
	}
	var indexes int
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='index' AND name='requests_time'").Scan(&indexes); err != nil || indexes != 1 {
		t.Fatal("reused requests lack their index", err)
	}
	// A third run reuses the reused generation in turn.
	third := analyzeBlob(t, dir, blobRules(t, "BLOB_MARKER"), blobLimits)
	if !third.ReconstructionReused || third.Alerts != 3 || !third.ReconstructedAt.Equal(first.ReconstructedAt) {
		t.Fatalf("third %+v", third)
	}
}

// rewriteEvidenceInPlace changes stream.jsonl without changing its size or
// modification time, so the source signature still matches. Only a run that
// replays the evidence sees the change, which shows whether replay ran.
func rewriteEvidenceInPlace(t *testing.T, dir, old, replacement string) {
	t.Helper()
	path := filepath.Join(dir, "tls", "stream.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != len(replacement) || !bytes.Contains(data, []byte(old)) {
		t.Fatal("bad evidence rewrite")
	}
	if err = os.WriteFile(path, bytes.ReplaceAll(data, []byte(old), []byte(replacement)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
}

func analysedURLs(t *testing.T, dir string) string {
	t.Helper()
	var urls []string
	for _, record := range observeStore(t, dir).Records {
		urls = append(urls, record.URL)
	}
	return strings.Join(sortStrings(urls), ",")
}

func TestReuseSkipsReplayOnlyWhenInputsMatch(t *testing.T) {
	// GET lines of the session are base64 inside stream.jsonl; rewrite one
	// base64 quantum that encodes "/page/1" into one encoding "/page/9".
	tamper := func(t *testing.T, dir string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, "tls", "stream.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.Split(data, []byte("\n"))
		var event session.RawEvent
		for _, line := range lines {
			if json.Unmarshal(line, &event) == nil && bytes.HasPrefix(event.Data, []byte("GET /page/1 ")) {
				before, _ := json.Marshal(event.Data)
				event.Data = bytes.Replace(event.Data, []byte("/page/1"), []byte("/page/9"), 1)
				after, _ := json.Marshal(event.Data)
				rewriteEvidenceInPlace(t, dir, string(before), string(after))
				return
			}
		}
		t.Fatal("request to tamper not found")
	}
	const original, tampered = "/page/1,/page/2,/upload?id=1", "/page/2,/page/9,/upload?id=1"
	cases := []struct {
		name   string
		before func(t *testing.T, dir string)
		limits replay.Options
		reused bool
	}{
		{"same inputs reuse", nil, blobLimits, true},
		{"request limit", nil, replay.Options{RequestLimit: 2 << 20, ResponseLimit: 1 << 20}, false},
		{"response limit", nil, replay.Options{RequestLimit: 1 << 20, ResponseLimit: 2 << 20}, false},
		{"reconstruction version", func(t *testing.T, dir string) { editMetadata(t, dir, "$.reconstruction_version", replay.Version+1) }, blobLimits, false},
		{"source signature", func(t *testing.T, dir string) { editMetadata(t, dir, "$.source_signature", "other") }, blobLimits, false},
		{"missing reconstruction table", func(t *testing.T, dir string) { execGeneration(t, dir, "DROP TABLE reconstruction") }, blobLimits, false},
		{"foreign requests layout", func(t *testing.T, dir string) {
			execGeneration(t, dir, "ALTER TABLE requests ADD COLUMN extra BLOB")
		}, blobLimits, false},
		{"removed generation", func(t *testing.T, dir string) {
			if err := os.Remove(mustAnalysisPath(t, dir)); err != nil {
				t.Fatal(err)
			}
		}, blobLimits, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir, _, _ := blobTestSession(t)
			analyzeBlob(t, dir, blobRules(t, "BLOB_MARKER"), blobLimits)
			tamper(t, dir)
			if test.before != nil {
				test.before(t, dir)
			}
			report := analyzeBlob(t, dir, blobRules(t, "NO_SUCH_MARKER"), test.limits)
			if report.ReconstructionReused != test.reused {
				t.Fatalf("reused=%v, want %v", report.ReconstructionReused, test.reused)
			}
			want := tampered
			if test.reused {
				want = original
			}
			if got := analysedURLs(t, dir); got != want {
				t.Fatalf("records %s, want %s", got, want)
			}
			if builds := analysisBuilds(t, dir); len(builds) != 0 {
				t.Fatal("build left behind", builds)
			}
		})
	}
}

// execGeneration edits the published generation in place, as a damaged or
// foreign file would look.
func execGeneration(t *testing.T, dir, statement string, args ...any) {
	t.Helper()
	db, err := sql.Open(index.Driver, mustAnalysisPath(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(statement, args...); err != nil {
		t.Fatal(err)
	}
}

func editMetadata(t *testing.T, dir, path string, value any) {
	t.Helper()
	execGeneration(t, dir, "UPDATE metadata SET data=json_set(data,?,?)", path, value)
}

// Builds no longer share decoder settings, so concurrent analyses of
// different sessions with different limits do not serialize or interfere.
func TestConcurrentAnalysesKeepTheirOwnLimits(t *testing.T) {
	type run struct {
		dir    string
		limit  int
		report analysisReport
		err    error
	}
	runs := make([]*run, 6)
	for i := range runs {
		dir, _, _ := blobTestSession(t)
		runs[i] = &run{dir: dir, limit: []int{1024, 1 << 20}[i%2]}
	}
	rs := blobRules(t, "BLOB_MARKER")
	var wg sync.WaitGroup
	for _, r := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.report, r.err = analyzeConfigured(context.Background(), r.dir, "", rs, time.Minute, 20, replay.Options{RequestLimit: r.limit, ResponseLimit: r.limit})
		}()
	}
	wg.Wait()
	for _, r := range runs {
		if r.err != nil {
			t.Fatal(r.err)
		}
		for _, record := range observeStore(t, r.dir).Records {
			if record.URL != "/upload?id=1" {
				continue
			}
			if record.Truncated != (r.limit == 1024) {
				t.Fatalf("limit %d: truncated=%v", r.limit, record.Truncated)
			}
		}
	}
}

func TestRecordJSONMatchesEncodingJSON(t *testing.T) {
	for _, record := range []Transaction{
		{ID: "a", Method: "GET", URL: "/", Request: []byte("GET / HTTP/1.1\r\n\r\n"), Response: []byte{0, 0xff, '"', '\\'}},
		{ID: "b", Request: []byte{1}},
		{ID: "c", Response: []byte("only")},
		{ID: "d"},
	} {
		meta := record
		meta.Request, meta.Response = nil, nil
		data, _ := json.Marshal(meta)
		for _, alerts := range []string{"", "[]", `[{"rule":"R","severity":"high","version":1,"field":"url","match":"x","decoding":0}]`} {
			var arg any
			if alerts != "" {
				arg = alerts
			}
			assembled, err := index.RecordJSON(data, record.Request, record.Response, arg)
			if err != nil {
				t.Fatal(err)
			}
			want := record
			if alerts != "" && alerts != "[]" {
				_ = json.Unmarshal([]byte(alerts), &want.Alerts)
			}
			for _, decode := range []func([]byte) (Transaction, error){session.DecodeTransaction, func(b []byte) (Transaction, error) {
				var t Transaction
				return t, json.Unmarshal(b, &t)
			}} {
				got, err := decode(assembled)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: got %+v, want %+v (%v)", assembled, got, want, err)
				}
			}
		}
	}
	if _, err := index.RecordJSON([]byte("[]"), []byte("x"), nil, nil); err == nil {
		t.Fatal("non-object metadata accepted")
	}
	if got, _ := index.RecordJSON([]byte("{}"), []byte("x"), nil, nil); string(got) != `{"request":"eA=="}` {
		t.Fatal(string(got))
	}
}
