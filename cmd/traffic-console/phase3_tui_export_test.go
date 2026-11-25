package main

import (
	"archive/zip"
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
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/packetio"
	"github.com/Sunmedalia/traffic/internal/session"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestLoadTUISummarySQLitePushdownBoundsAndCache(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// Insert > tuiSourceLimit distinct alerting sources so SQLite LIMIT+1 capping is exercised.
	for i := range tuiSourceLimit + 15 {
		sev := "medium"
		rule := "FILE-001"
		if i < 25 {
			sev = "high"
			rule = "SQLI-001"
		}
		putTUITransaction(t, writer, Transaction{
			ID:     fmt.Sprintf("src-%03d", i),
			Time:   now.Add(time.Duration(i) * time.Second),
			Client: fmt.Sprintf("198.51.%d.%d:%d", i/200, i%200+1, 10000+i),
			Method: "GET",
			Host:   "demo",
			URL:    fmt.Sprintf("/p/%d", i),
			Status: 200,
			Alerts: []Alert{{Rule: rule, Severity: sev, Match: fmt.Sprintf("m-%d", i)}},
		})
	}
	if err := os.WriteFile(filepath.Join(writer.dir, "status.json"), []byte(`{"state":"stopped","transactions":215}`), 0600); err != nil {
		t.Fatal(err)
	}

	reader, err := openStore(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.db.Close()

	sum, err := loadTUISummary(context.Background(), reader, tuiFilter{})
	if err != nil {
		t.Fatalf("loadTUISummary failed: %v", err)
	}
	if sum.AlertRequests != tuiSourceLimit+15 {
		t.Fatalf("AlertRequests = %d, want %d", sum.AlertRequests, tuiSourceLimit+15)
	}
	if sum.Levels[3] != 25 || sum.Levels[2] != tuiSourceLimit+15-25 {
		t.Fatalf("Levels = %+v", sum.Levels)
	}
	if len(sum.Sources) != tuiSourceLimit || !sum.SourcesCapped {
		t.Fatalf("Sources len=%d capped=%v, want %d/true", len(sum.Sources), sum.SourcesCapped, tuiSourceLimit)
	}
	if len(sum.Recent) != tuiRecentLimit || sum.Recent[0].ID != "src-024" || sum.Recent[0].Rule != "SQLI-001" {
		t.Fatalf("Recent len=%d first=%+v", len(sum.Recent), sum.Recent[0])
	}
	if len(sum.Rules) != 2 || sum.Rules[0].Rule != "SQLI-001" || sum.Rules[0].Match != "m-24" || sum.Rules[1].Rule != "FILE-001" {
		t.Fatalf("Rules = %+v", sum.Rules)
	}

	// Finished session reuses the cached *tuiSummary pointer.
	sum2, err := loadTUISummary(context.Background(), reader, tuiFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if sum2 != sum {
		t.Fatalf("expected cached *tuiSummary for finished session")
	}

	// Mutating the session invalidates the finished-session summary cache.
	putTUITransaction(t, writer, Transaction{
		ID:     "src-extra",
		Time:   now.Add(10 * time.Minute),
		Client: "203.0.113.9:9999",
		Method: "GET",
		Host:   "demo",
		URL:    "/extra",
		Status: 200,
		Alerts: []Alert{{Rule: "SQLI-001", Severity: "high", Match: "latest-match"}},
	})
	sum3, err := loadTUISummary(context.Background(), reader, tuiFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if sum3 == sum || sum3.AlertRequests != tuiSourceLimit+16 || sum3.Rules[0].Match != "latest-match" {
		t.Fatalf("summary cache did not invalidate: alerts=%d match=%q", sum3.AlertRequests, sum3.Rules[0].Match)
	}
}

func TestTUIDetailLightweightMetadataPolling(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC()
	putTUITransaction(t, writer, Transaction{
		ID:         "rec-1",
		Time:       now,
		Client:     "192.0.2.1:1234",
		Method:     "GET",
		Host:       "demo",
		URL:        "/big",
		Status:     0,
		Incomplete: true,
		Request:    []byte("GET /big HTTP/1.1\r\nHost: demo\r\n\r\n" + strings.Repeat("A", 8192)),
	})

	reader, err := openStore(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.db.Close()

	// Initial load fetches full detail + metadata.
	first, err := loadTUISnapshotWithMeta(context.Background(), reader, tuiFilter{}, false, 0, "rec-1", nil, nil)
	if err != nil || first.Detail == nil || first.DetailMeta == nil || first.DetailUnchanged {
		t.Fatalf("initial detail load: %+v err=%v", first, err)
	}

	// Second load with matching metadata skips fetching and decoding records.data.
	second, err := loadTUISnapshotWithMeta(context.Background(), reader, tuiFilter{}, false, 0, "rec-1", first.DetailMeta, nil)
	if err != nil || !second.DetailUnchanged || second.Detail != nil || second.DetailMeta == nil {
		t.Fatalf("expected DetailUnchanged with nil Detail, got unchanged=%v detail=%v err=%v", second.DetailUnchanged, second.Detail, err)
	}

	// applySnapshot preserves the existing Detail pointer when DetailUnchanged is set.
	m := &tuiModel{ctx: context.Background(), store: reader, refresh: time.Second, details: true, detailID: "rec-1", width: 120, height: 30}
	m.applySnapshot(first)
	origPtr := m.snapshot.Detail
	m.applySnapshot(second)
	if m.snapshot.Detail != origPtr {
		t.Fatalf("applySnapshot did not retain existing Detail pointer on unchanged metadata")
	}

	// Once response arrives (status changes 0 -> 200), metadata differs and full detail is re-fetched.
	putTUITransaction(t, writer, Transaction{
		ID:         "rec-1",
		Time:       now,
		Client:     "192.0.2.1:1234",
		Method:     "GET",
		Host:       "demo",
		URL:        "/big",
		Status:     200,
		Incomplete: false,
		Request:    []byte("GET /big HTTP/1.1\r\nHost: demo\r\n\r\n" + strings.Repeat("A", 8192)),
		Response:   []byte("HTTP/1.1 200 OK\r\n\r\ndone"),
	})
	third, err := loadTUISnapshotWithMeta(context.Background(), reader, tuiFilter{}, false, 0, "rec-1", m.detailMeta, nil)
	if err != nil || third.DetailUnchanged || third.Detail == nil || third.Detail.Status != 200 {
		t.Fatalf("expected full reload after status update: unchanged=%v detail=%+v err=%v", third.DetailUnchanged, third.Detail, err)
	}
}

func TestWebExportStreamingAndConflictBeforeHeaders(t *testing.T) {
	writer := tuiTestStore(t)
	now := time.Now().UTC()
	putTUITransaction(t, writer, Transaction{
		ID:       "stream-1",
		Time:     now,
		Client:   "192.0.2.1:4000",
		Method:   "GET",
		Host:     "demo",
		URL:      "/evidence",
		Status:   200,
		Request:  []byte("GET /evidence HTTP/1.1\r\nHost: demo\r\n\r\n"),
		Response: []byte("HTTP/1.1 200 OK\r\n\r\nok"),
	})
	if err := os.WriteFile(filepath.Join(writer.dir, "status.json"), []byte(`{"state":"stopped","transactions":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(writer.dir, "capture.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	web := newWebServer([]string{writer.dir}, "stream-export-token-0123456789", time.Second)
	defer web.close()
	server := httptest.NewServer(web.handler())
	defer server.Close()
	sid := webSessionID(writer.dir)

	// Normal streaming export returns a valid ZIP with all expected members.
	status, body, header := webGet(t, server, web.token, "/api/sessions/"+sid+"/requests/stream-1/export")
	if status != http.StatusOK || header.Get("Content-Type") != "application/zip" {
		t.Fatalf("stream export status=%d ct=%q body=%s", status, header.Get("Content-Type"), body)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("invalid streamed zip: %v", err)
	}
	members := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		members[f.Name], err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"event.json", "request.http", "response.http", "evidence.json", "sha256.json"} {
		if _, ok := members[want]; !ok {
			t.Fatalf("streamed zip missing %s", want)
		}
	}

	// While capture.lock is exclusively held, validation fails BEFORE ZIP headers are written (returns 409 JSON).
	lock, err := os.OpenFile(filepath.Join(writer.dir, "capture.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := session.LockFile(lock, true); err != nil {
		t.Fatal(err)
	}
	defer session.UnlockFile(lock)

	status, body, header = webGet(t, server, web.token, "/api/sessions/"+sid+"/requests/stream-1/export")
	if status != http.StatusConflict || !strings.HasPrefix(header.Get("Content-Type"), "application/json") {
		t.Fatalf("locked export status=%d ct=%q body=%s, want 409 json", status, header.Get("Content-Type"), body)
	}
}

func TestExportPrunesOutOfWindowPCAPSegments(t *testing.T) {
	s := tuiTestStore(t)
	if err := os.WriteFile(filepath.Join(s.dir, "capture.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	packetsDir := filepath.Join(s.dir, "packets")
	if err := os.MkdirAll(packetsDir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	pkt := evidencePacket(t, false, 12345)

	writeSeg := func(name string, ts time.Time, corruptTail bool) {
		f, err := os.Create(filepath.Join(packetsDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := packetio.WriteHeader(f, 65535, uint32(layers.LinkTypeEthernet)); err != nil {
			t.Fatal(err)
		}
		w := pcapgo.NewWriterNanos(f)
		ci := gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(pkt), Length: len(pkt)}
		if err := w.WritePacket(ci, pkt); err != nil {
			t.Fatal(err)
		}
		if corruptTail {
			// Appending truncated garbage would cause a non-last segment scan to fail if not pruned.
			if _, err := f.Write([]byte{0x01, 0x02, 0x03}); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// Segment 1 (T-10m) is before window because segment 2 starts at T-2m (still < T-1m).
	// Segment 2 (T-2m) overlaps? No, segment 3 starts at T, so segment 2's next starts at T >= T-1m -> scanned.
	// Segment 3 (T) is inside [T-1m, T+1m] -> matched and exported.
	// Segment 4 (T+10m) starts strictly after T+1m -> pruned without reading past packet 1.
	writeSeg("any-0001.pcap", now.Add(-10*time.Minute), true)
	writeSeg("any-0002.pcap", now.Add(-2*time.Minute), false)
	writeSeg("any-0003.pcap", now, false)
	writeSeg("any-0004.pcap", now.Add(10*time.Minute), true)

	tx := Transaction{
		ID:            "prune-1",
		Time:          now,
		Client:        "192.0.2.1:12345",
		LocalEndpoint: "192.0.2.2:80",
		Source:        "pcap:any",
	}
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "pruned.zip")
	if err := exportEvidence(s, tx, raw, out); err != nil {
		t.Fatalf("exportEvidence failed (pruned segment may have been scanned): %v", err)
	}

	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	found := map[string]bool{}
	for _, f := range zr.File {
		found[f.Name] = true
	}
	if !found["packets/any-0003.pcap"] {
		t.Fatalf("expected packets/any-0003.pcap in archive, got %v", found)
	}
	if found["packets/any-0001.pcap"] || found["packets/any-0002.pcap"] || found["packets/any-0004.pcap"] {
		t.Fatalf("unexpected out-of-window segment in archive: %v", found)
	}
}
