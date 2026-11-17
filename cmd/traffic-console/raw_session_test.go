package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/replay"
	"github.com/Sunmedalia/traffic/internal/session"
)

func rawTestSession(t *testing.T, events []session.RawEvent) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{"manifest.json": `{"capture_mode":"raw","layout_version":3,"capture_ports":[443],"local_addresses":["127.0.0.1"]}`, "status.json": `{"state":"stopped","transactions":0}`, "capture.lock": ""} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "tls"), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(dir, "tls", "stream.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, event := range events {
		if err = encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRawTLSIsReconstructedAndCanBeReanalyzedWithLargerLimits(t *testing.T) {
	now := time.Now().UTC()
	target := &session.Target{PID: 321, ID: "321:original", Service: "nginx", Ports: []int{443}}
	body := bytes.Repeat([]byte("x"), (1<<20)+80000)
	body = append(body, []byte("LOCAL_TAIL")...)
	request := append([]byte(fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: example\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	events := []session.RawEvent{{Version: 1, Source: "source-a", Type: "source", Backend: "ecapture", Target: target, Time: now},
		{Version: 1, Source: "source-a", Type: "data", Connection: "c", Direction: "read", Data: request, Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Time: now},
		{Version: 1, Source: "source-a", Type: "data", Connection: "c", Direction: "write", Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Time: now.Add(time.Millisecond)},
		{Version: 1, Source: "source-a", Type: "end", Time: now.Add(2 * time.Millisecond)}}
	dir := rawTestSession(t, events)
	before, err := os.ReadFile(filepath.Join(dir, "tls", "stream.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if initial.analysisNote == "" {
		t.Fatal("raw session did not request reconstruction")
	}
	initial.db.Close()
	rs, err := validateRuleContent("- id: LOCAL-TAIL\n  version: 1\n  severity: high\n  field: request.body\n  pattern: LOCAL_TAIL\n")
	if err != nil {
		t.Fatal(err)
	}
	first, err := analyzeConfigured(context.Background(), dir, "", rs, time.Minute, 20, replay.Options{RequestLimit: 1 << 20, ResponseLimit: 1 << 20})
	if err != nil || first.Transactions != 1 || first.Alerts != 0 || !first.Reconstructed {
		t.Fatal("first reconstruction", first, err)
	}
	reader, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.db.Close()
	second, err := analyzeConfigured(context.Background(), dir, "", rs, time.Minute, 20, replay.Options{RequestLimit: 2 << 20, ResponseLimit: 2 << 20})
	if err != nil || second.Transactions != 1 || second.Alerts != 1 {
		t.Fatal("larger local reconstruction", second, err)
	}
	// A reader pins the old generation, so its counters and rows stay consistent.
	var oldAlerts int
	if err = reader.db.QueryRow("SELECT sum(alert) FROM requests").Scan(&oldAlerts); err != nil || oldAlerts != 0 {
		t.Fatal("old reader mixed generations", oldAlerts, err)
	}
	current, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer current.db.Close()
	var raw []byte
	var record Transaction
	if err = current.db.QueryRow("SELECT data FROM requests").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.Request, request) || record.Status != 200 || record.Truncated || record.TargetID != target.ID || len(record.Alerts) != 1 {
		t.Fatalf("reconstruction mismatch %+v", record)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "tls", "stream.jsonl"))
	if !bytes.Equal(before, after) {
		t.Fatal("analysis rewrote raw events")
	}
	if _, err = os.Stat(filepath.Join(dir, "index.sqlite")); !os.IsNotExist(err) {
		t.Fatal("console wrote a capture-side index")
	}
}

func TestRawIISAPIEventsArePairedOnlyLocally(t *testing.T) {
	now := time.Now().UTC()
	target := &session.Target{PID: 77, ID: "77:start", Service: "iis", Ports: []int{443}}
	events := []session.RawEvent{{Version: 1, Source: "iis-1", Type: "source", Backend: "iis", Target: target, Time: now}}
	for _, event := range []session.IISEvent{{Type: "request", ID: "a", Connection: "c", Method: "GET", URL: "/.env", Client: "192.0.2.1:80", Local: "127.0.0.1:443", Time: now}, {Type: "request-end", ID: "a"}, {Type: "response", ID: "a", Status: 200}, {Type: "response-body", ID: "a", Data: []byte("ok")}, {Type: "response-end", ID: "a"}} {
		copy := event
		events = append(events, session.RawEvent{Version: 1, Source: "iis-1", Type: "iis", Time: now, IIS: &copy})
	}
	dir := rawTestSession(t, events)
	rs, err := rulesFromYAML(nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := analyzeSessionRules(context.Background(), dir, "", rs, time.Minute, 20)
	if err != nil || report.Transactions != 1 || report.Alerts != 1 {
		t.Fatal(report, err)
	}
}

func TestRawBackendMetadataAndLossBoundary(t *testing.T) {
	for _, backend := range []string{"java-agent", "openssl-preload", "ecapture"} {
		t.Run(backend, func(t *testing.T) {
			now := time.Now().UTC()
			target := &session.Target{PID: 42, ID: "42:original", Service: "tomcat", Ports: []int{443}}
			events := []session.RawEvent{{Version: 1, Time: now, Source: "source", Type: "source", Backend: backend, Target: target}}
			add := func(kind, direction, data string) {
				events = append(events, session.RawEvent{Version: 1, Time: now, Source: "source", Type: kind, Connection: "c", Direction: direction, Data: []byte(data), Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Count: 1})
			}
			add("data", "read", "GET /before-loss HTTP/1.1\r\nHost: test\r\n\r\n")
			add("loss", "", "")
			add("data", "read", "GET /after-loss HTTP/1.1\r\nHost: test\r\n\r\n")
			add("data", "write", "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
			add("end", "", "")
			dir := rawTestSession(t, events)
			rs, _ := rulesFromYAML(nil)
			report, err := analyzeSessionRules(context.Background(), dir, "", rs, time.Minute, 20)
			if err != nil || report.Transactions != 2 {
				t.Fatal(report, err)
			}
			store, err := openStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.db.Close()
			rows, err := store.db.Query("SELECT data FROM requests")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			for rows.Next() {
				var data []byte
				var record Transaction
				if err = rows.Scan(&data); err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(data, &record); err != nil {
					t.Fatal(err)
				}
				want := backend
				if want == "ecapture" {
					want = "openssl"
				}
				if record.Backend != want || record.Service != "tomcat" || record.TargetID != target.ID || !record.Incomplete {
					t.Fatalf("metadata/loss mismatch %+v", record)
				}
				if record.URL == "/before-loss" && record.Status != 0 {
					t.Fatal("paired across recorded loss", record)
				}
				if record.URL == "/after-loss" && record.Status != 201 {
					t.Fatal("new request not paired", record)
				}
			}
			if err = rows.Err(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCancelledPublishKeepsPreviousGeneration(t *testing.T) {
	dir, source := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "analysis.sqlite"), []byte("generation"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishAnalysis(context.Background(), dir, source); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, analysisPointer))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := publishAnalysis(ctx, dir, source); err != context.Canceled {
		t.Fatal("cancelled publication succeeded", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, analysisPointer))
	if !bytes.Equal(before, after) {
		t.Fatal("cancelled publication changed pointer")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "analysis-*.sqlite"))
	if len(files) != 1 {
		t.Fatal("failed generation not removed", files)
	}
}

func TestWebReconstructsRawSessionBeforeServingRequests(t *testing.T) {
	now := time.Now().UTC()
	target := &session.Target{PID: 12, ID: "12:start", Service: "nginx", Ports: []int{443}}
	dir := rawTestSession(t, []session.RawEvent{
		{Version: 1, Time: now, Source: "a", Type: "source", Backend: "ecapture", Target: target},
		{Version: 1, Time: now, Source: "a", Type: "data", Connection: "c", Direction: "read", Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Data: []byte("GET /.env HTTP/1.1\r\nHost: test\r\n\r\n")},
		{Version: 1, Time: now, Source: "a", Type: "data", Connection: "c", Direction: "write", Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")},
	})
	web := newWebServer([]string{dir}, "raw-web-test", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	path := "/api/sessions/" + webSessionID(dir)
	code, data := ruleRequest(t, server, web.token, "GET", path+"/requests", nil)
	if code != 200 || !bytes.Contains(data, []byte(`"count":0`)) {
		t.Fatal(code, string(data))
	}
	code, data = ruleRequest(t, server, web.token, "POST", path+"/analyze", map[string]string{})
	if code != 202 {
		t.Fatal(code, string(data))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, data = ruleRequest(t, server, web.token, "GET", "/api/analysis", nil)
		var state struct {
			Job webAnalysisJob `json:"job"`
		}
		if err := json.Unmarshal(data, &state); err != nil || code != 200 {
			t.Fatal(code, string(data), err)
		}
		if state.Job.State != "running" {
			if state.Job.State != "succeeded" || state.Job.Report == nil || !state.Job.Report.Reconstructed {
				t.Fatal(state.Job)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("raw Web analysis timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
	code, data = ruleRequest(t, server, web.token, "GET", path+"/requests?alerts=1", nil)
	if code != 200 || !bytes.Contains(data, []byte(`"count":1`)) {
		t.Fatal(code, string(data))
	}
}
