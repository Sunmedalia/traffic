package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

func TestMergedTimeRangePreservesTUIAndWebBoundaries(t *testing.T) {
	s := tuiTestStore(t)
	at := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	putTUITransaction(t, s, Transaction{ID: "before", Time: at.Add(-time.Second)})
	putTUITransaction(t, s, Transaction{ID: "boundary", Time: at})
	putTUITransaction(t, s, Transaction{ID: "after", Time: at.Add(time.Second)})
	filter := tuiFilter{Until: at.Format(indexTimeFormat)}
	result, err := loadTUISnapshot(context.Background(), s, filter, false, 0, "", nil)
	if err != nil || result.Count != 2 {
		t.Fatalf("TUI inclusive end: %+v, %v", result, err)
	}
	web, _, err := webFilter(httptest.NewRequest("GET", "/?until="+at.Format(time.RFC3339), nil))
	if err != nil {
		t.Fatal(err)
	}
	result, err = loadTUISnapshot(context.Background(), s, web, false, 0, "", nil)
	if err != nil || result.Count != 1 || result.Rows[0].ID != "before" {
		t.Fatalf("Web exclusive end: %+v, %v", result, err)
	}
}

func TestMergedTUIRetainsCaptureDiagnostics(t *testing.T) {
	m := tuiModel{}
	m.snapshot.Stats = Stats{
		State: "interrupted", DrainState: "unverified",
		GapCounts:  map[string]uint64{"ecapture/drain_unconfirmed/shutdowns": 1},
		ProbeExits: map[string]session.ProbeExit{"ecapture": {RuntimeState: "transport drain not confirmed"}},
	}
	health := m.healthContent()
	for _, want := range []string{"数据排空", "unverified", "drain_unconfirmed", "transport drain not confirmed"} {
		if !strings.Contains(health, want) {
			t.Fatalf("missing health diagnostic %q: %s", want, health)
		}
	}
	if level, _ := m.tuiHealth(); level != 2 {
		t.Fatal("interrupted capture must remain critical")
	}
	txn := Transaction{ID: "h2", Protocol: "HTTP/2", StreamID: 7, IntegrityReasons: []string{"frame_gap"}}
	m.detailID, m.snapshot.Detail = txn.ID, &txn
	detail := m.detailContent()
	for _, want := range []string{"HTTP/2", "stream ID 7", "frame_gap"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("missing transaction diagnostic %q: %s", want, detail)
		}
	}
}
