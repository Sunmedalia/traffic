package main

import (
	"archive/zip"
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
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
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
	for _, event := range []session.IISEvent{{Type: "probe-gap", Reason: "unmatched_completion", Kind: "unknown", Count: 10}, {Type: "request", ID: "a", Connection: "c", Method: "GET", URL: "/.env", Client: "192.0.2.1:80", Local: "127.0.0.1:443", Time: now}, {Type: "request-end", ID: "a"}, {Type: "response", ID: "a", Status: 200}, {Type: "response-body", ID: "a", Data: []byte("ok")}, {Type: "response-end", ID: "a"}} {
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

func TestRawDiscoveryAndSummaryCachesFollowAnalysisGeneration(t *testing.T) {
	now := time.Now().UTC()
	target := &session.Target{PID: 42, ID: "42:start", Service: "nginx", Ports: []int{443}}
	dir := rawTestSession(t, []session.RawEvent{
		{Version: 1, Time: now, Source: "a", Type: "source", Backend: "ecapture", Target: target},
		{Version: 1, Time: now, Source: "a", Type: "data", Connection: "c", Direction: "read", Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Data: []byte("GET /local-marker HTTP/1.1\r\nHost: test\r\n\r\n")},
		{Version: 1, Time: now, Source: "a", Type: "data", Connection: "c", Direction: "write", Local: "127.0.0.1:443", Client: "192.0.2.1:1234", Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")},
	})
	cache := newDiscoveryCache()
	initial := discoverSessions(context.Background(), []string{dir}, cache)
	if len(initial.Entries) != 1 || initial.Entries[0].CountsKnown {
		t.Fatal(initial)
	}
	builtins, _ := rulesFromYAML(nil)
	if _, err := analyzeSessionRules(context.Background(), dir, "", builtins, time.Minute, 20); err != nil {
		t.Fatal(err)
	}
	web := newWebServer([]string{dir}, "raw-cache-test", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	summary := func(want int) {
		t.Helper()
		code, data := ruleRequest(t, server, web.token, "GET", "/api/sessions/"+webSessionID(dir)+"/summary", nil)
		var counts struct {
			Total   int `json:"total"`
			Alerted int `json:"alerted"`
		}
		if err := json.Unmarshal(data, &counts); err != nil || code != 200 || counts.Total != 1 || counts.Alerted != want {
			t.Fatal(code, string(data), err)
		}
	}
	summary(0)
	first := discoverSessions(context.Background(), []string{dir}, cache)
	if len(first.Entries) != 1 || !first.Entries[0].CountsKnown || first.Entries[0].Stats.Transactions != 1 || first.Entries[0].Stats.Alerts != 0 {
		t.Fatal(first)
	}
	rules, _ := validateRuleContent(testManagedRules)
	if _, err := analyzeSessionRules(context.Background(), dir, "", rules, time.Minute, 20); err != nil {
		t.Fatal(err)
	}
	summary(1)
	second := discoverSessions(context.Background(), []string{dir}, cache)
	if len(second.Entries) != 1 || second.Entries[0].Stats.Alerts != 1 || second.Entries[0].Stats.Transactions != 1 {
		t.Fatal(second)
	}
	// Reusing the cache without changes must retain reconstructed counts as well.
	third := discoverSessions(context.Background(), []string{dir}, cache)
	if len(third.Entries) != 1 || !third.Entries[0].CountsKnown || third.Entries[0].Stats.Alerts != 1 || third.Entries[0].Stats.Transactions != 1 {
		t.Fatal(third)
	}
}

func TestRawReplayRecoversNewHTTP2AfterLoss(t *testing.T) {
	now := time.Now().UTC()
	target := &session.Target{ID: "nginx", Service: "nginx"}
	events := []session.RawEvent{{Version: 1, Source: "one", Backend: "ecapture", Type: "source", Target: target, Time: now}}
	add := func(connection, direction string, data []byte) {
		events = append(events, session.RawEvent{Version: 1, Source: "one", Type: "data", Direction: direction,
			Connection: connection, Local: "127.0.0.1:443", Client: "192.0.2.1:50001", Data: data, Time: now,
			Incomplete: len(events) > 2})
	}
	http2Side := func(preface bool, fields ...hpack.HeaderField) []byte {
		var out, header bytes.Buffer
		if preface {
			out.WriteString(http2.ClientPreface)
		}
		encoder := hpack.NewEncoder(&header)
		for _, field := range fields {
			if err := encoder.WriteField(field); err != nil {
				t.Fatal(err)
			}
		}
		framer := http2.NewFramer(&out, nil)
		if err := framer.WriteSettings(); err != nil {
			t.Fatal(err)
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: true, BlockFragment: header.Bytes()}); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	old := http2Side(true, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":scheme", Value: "https"}, hpack.HeaderField{Name: ":path", Value: "/old"}, hpack.HeaderField{Name: ":authority", Value: "example"})
	add("old", "read", old)
	events = append(events, session.RawEvent{Version: 1, Source: "one", Type: "loss", Time: now, Reason: "receive_queue_shed", Unit: "messages", Count: 5})
	fresh := http2Side(true, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":scheme", Value: "https"}, hpack.HeaderField{Name: ":path", Value: "/fresh"}, hpack.HeaderField{Name: ":authority", Value: "example"})
	add("fresh", "read", fresh[:3])
	add("fresh", "read", fresh[3:])
	response := http2Side(false, hpack.HeaderField{Name: ":status", Value: "200"})
	add("old", "write", response)
	add("fresh", "write", response)

	dir := rawTestSession(t, events)
	stream := filepath.Join(dir, "tls", "stream.jsonl")
	file, err := os.OpenFile(stream, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString(`{"source":"one","type":`)
	if closeErr := file.Close(); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	before, err := os.ReadFile(stream)
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := rulesFromYAML(nil)
	report, err := analyzeSessionRules(context.Background(), dir, "", rs, time.Minute, 20)
	if err != nil || report.Transactions != 2 {
		t.Fatal(report, err)
	}
	if counts := report.Reconstruction.GapCounts; counts["ecapture/receive_queue_shed/messages"] != 5 || counts["tls/truncated_raw_tail/records"] != 1 {
		t.Fatalf("missing diagnostics: %+v", counts)
	}
	store, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	for _, url := range []string{"/old", "/fresh"} {
		var raw []byte
		var transaction Transaction
		if err := store.db.QueryRow("SELECT data FROM requests WHERE json_extract(data, '$.url')=?", url).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &transaction); err != nil {
			t.Fatal(err)
		}
		fresh := url == "/fresh"
		if transaction.Incomplete == fresh || (transaction.Status == 200) != fresh {
			t.Fatalf("unexpected reconstruction state for %s: %+v", url, transaction)
		}
	}
	after, err := os.ReadFile(stream)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("recovery changed the raw evidence: %v", err)
	}
}

func TestAnalyzeStatusTUIAndExportSurfaceStalledCaptureWarnings(t *testing.T) {
	started := time.Date(2026, 11, 18, 2, 48, 59, 0, time.UTC)
	pktTime := started.Add(190 * time.Millisecond)
	stopped := started.Add(75 * time.Second)
	target := &session.Target{PID: 6092, ID: "6092:133000", Service: "iis", Ports: []int{443}}
	events := []session.RawEvent{
		{Version: 1, Source: "iis-1", Type: "source", Backend: "iis", Target: target, Time: pktTime},
		{Version: 1, Source: "iis-1", Type: "iis", Time: pktTime, IIS: &session.IISEvent{Type: "request", ID: "req-1", Connection: "c1", Method: "GET", URL: "/?n=1", Client: "127.0.0.1:50001", Local: "127.0.0.1:443", Time: pktTime}},
		{Version: 1, Source: "iis-1", Type: "iis", Time: pktTime, IIS: &session.IISEvent{Type: "request-end", ID: "req-1"}},
		{Version: 1, Source: "iis-1", Type: "iis", Time: pktTime, IIS: &session.IISEvent{Type: "response", ID: "req-1", Status: 200}},
		{Version: 1, Source: "iis-1", Type: "iis", Time: pktTime, IIS: &session.IISEvent{Type: "response-body", ID: "req-1", Data: []byte("ok")}},
		{Version: 1, Source: "iis-1", Type: "iis", Time: pktTime, IIS: &session.IISEvent{Type: "response-end", ID: "req-1"}},
	}
	dir := rawTestSession(t, events)

	// Write a PCAP with a single early packet and a v0.1.3-style status.json that froze after 0.19s.
	pktDir := filepath.Join(dir, "packets")
	if err := os.MkdirAll(pktDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Minimal valid Raw IPv4 TCP SYN packet (40 bytes) so replayPacketFiles records timestamps.
	rawPkt := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x7c, 0xcd,
		127, 0, 0, 1, 127, 0, 0, 1,
		0xc3, 0x51, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	var pcapBuf bytes.Buffer
	pcapHeader := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
		0xff, 0xff, 0x00, 0x00, 101, 0x00, 0x00, 0x00, // LinkTypeRaw = 101
	}
	pcapBuf.Write(pcapHeader)
	recHdr := make([]byte, 16)
	sec := uint32(pktTime.Unix())
	usec := uint32(pktTime.Nanosecond() / 1000)
	recHdr[0], recHdr[1], recHdr[2], recHdr[3] = byte(sec), byte(sec>>8), byte(sec>>16), byte(sec>>24)
	recHdr[4], recHdr[5], recHdr[6], recHdr[7] = byte(usec), byte(usec>>8), byte(usec>>16), byte(usec>>24)
	recHdr[8] = byte(len(rawPkt))
	recHdr[12] = byte(len(rawPkt))
	pcapBuf.Write(recHdr)
	pcapBuf.Write(rawPkt)
	if err := os.WriteFile(filepath.Join(pktDir, "windivert-000000000001.pcap"), pcapBuf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	status := session.Stats{
		Started:    started,
		Stopped:    stopped,
		State:      "stopped",
		Packets:    105,
		DrainState: "confirmed",
		StopReason: "duration",
		GapCounts:  map[string]uint64{"pcap/drop_counter_unavailable/sources": 1},
		ProbeExits: map[string]session.ProbeExit{
			"6092:133000": {
				HookBased:         true,
				DataDrained:       true,
				HooksRemoved:      true,
				ScriptUnloaded:    false,
				TransportDetached: false,
				RuntimeState:      "hooks_removed_runtime_lingering",
			},
		},
	}
	statusBytes, _ := json.Marshal(status)
	if err := os.WriteFile(filepath.Join(dir, "status.json"), statusBytes, 0600); err != nil {
		t.Fatal(err)
	}

	rs, err := rulesFromYAML(nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := analyzeSessionRules(context.Background(), dir, "", rs, time.Minute, 20)
	if err != nil {
		t.Fatal(err)
	}
	if report.Reconstruction == nil || report.Reconstruction.Packets != 1 || report.Reconstruction.LastPacketAt.IsZero() {
		t.Fatalf("expected reconstructed packet timestamps, got %+v", report.Reconstruction)
	}
	if len(report.IntegrityWarnings) < 3 {
		t.Fatalf("expected >=3 integrity warnings on stalled session, got %v", report.IntegrityWarnings)
	}

	store, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	snap, err := loadTUISnapshot(context.Background(), store, tuiFilter{}, false, 0, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Stats.IntegrityWarnings) < 3 {
		t.Fatalf("TUI snapshot missing integrity warnings: %v", snap.Stats.IntegrityWarnings)
	}
	m := tuiModel{store: store, snapshot: snap}
	lvl, reasons := m.tuiHealth()
	if lvl < 1 || len(reasons) == 0 {
		t.Fatalf("TUI health failed to flag stalled session: level=%d reasons=%v", lvl, reasons)
	}

	var txID string
	var txRaw []byte
	if err := store.db.QueryRow("SELECT id, data FROM requests LIMIT 1").Scan(&txID, &txRaw); err != nil {
		t.Fatal(err)
	}
	var txRecord Transaction
	if err := json.Unmarshal(txRaw, &txRecord); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "evidence.zip")
	if err := exportEvidence(store, txRecord, txRaw, zipPath); err != nil {
		t.Fatal(err)
	}
	evidence, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer evidence.Close()
	manifest, err := evidence.Open("evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	defer manifest.Close()
	var note struct {
		Warnings []string `json:"session_integrity_warnings"`
	}
	if err := json.NewDecoder(manifest).Decode(&note); err != nil {
		t.Fatal(err)
	}
	if len(note.Warnings) < 3 {
		t.Fatalf("evidence manifest missing integrity warnings: %v", note.Warnings)
	}
}
