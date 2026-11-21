package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
)

// parallelTestSession stores transactions whose alerts depend on rule
// matching and, for SCAN-001, on processing order.
func parallelTestSession(t *testing.T, count int) *Store {
	t.Helper()
	writer := tuiTestStore(t)
	base := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	for i := range count {
		url := fmt.Sprintf("/page/%d", i%37)
		status := 200
		switch i % 5 {
		case 0, 2, 3:
			url, status = fmt.Sprintf("/probe-%d", i), 404
		case 1:
			url = "/search?q=1%20union%20select%202"
		}
		request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: demo\r\n\r\n", url)
		// Equal timestamps exercise the id tie-break of the source order.
		putTUITransaction(t, writer, Transaction{
			ID: fmt.Sprintf("tx-%04d", i), Time: base.Add(time.Duration(i/3) * time.Second),
			Client: fmt.Sprintf("192.0.2.%d:4000", i%3), Method: "GET", Host: "demo", URL: url, Status: status,
			Request: []byte(request), Response: []byte(fmt.Sprintf("HTTP/1.1 %d X\r\nContent-Length: 0\r\n\r\n", status)),
		})
	}
	os.WriteFile(filepath.Join(writer.dir, "capture.lock"), nil, 0600)
	return writer
}

func TestParallelAnalysisMatchesSerialOrder(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	writer := parallelTestSession(t, 900)
	rs, err := rulesFromYAML(nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := analyzeSessionRules(context.Background(), writer.dir, "", rs, time.Minute, 20)
	if err != nil {
		t.Fatal(err)
	}
	// Serial reference over the same source order.
	rows, err := writer.db.Query("SELECT id,data FROM requests ORDER BY time,id")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	want := map[string]string{}
	scanner := &scanTracker{clients: map[string]*scanState{}}
	total, scansSeen := 0, 0
	for rows.Next() {
		var id string
		var raw []byte
		var record Transaction
		if err = rows.Scan(&id, &raw); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		alerts := detectWithLimits(record, rs, requestLimit, responseLimit)
		if alert := scanWithState(record, scanner, time.Minute, 20); alert != nil {
			alerts = append(alerts, *alert)
			scansSeen++
		}
		if alerts == nil {
			alerts = []Alert{}
		}
		encoded, _ := json.Marshal(alerts)
		order = append(order, id)
		want[id] = string(encoded)
		total += len(alerts)
	}
	rows.Close()
	if scansSeen == 0 {
		t.Fatal("fixture never triggers SCAN-001")
	}
	if report.ScanSkipped != nil {
		t.Fatalf("scan limits reported without being reached: %+v", report.ScanSkipped)
	}
	if report.Transactions != uint64(len(order)) || report.Alerts != uint64(total) {
		t.Fatalf("report %d transactions %d alerts, want %d and %d", report.Transactions, report.Alerts, len(order), total)
	}
	path, err := analysisDatabasePath(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open(index.Driver, analysisURL(path, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range []string{"entries", "results"} {
		rows, err := db.Query("SELECT id,alerts FROM " + table + " ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var id, alerts string
			if err = rows.Scan(&id, &alerts); err != nil {
				t.Fatal(err)
			}
			if alerts != want[id] {
				t.Fatalf("%s %s alerts %s, want %s", table, id, alerts, want[id])
			}
			got = append(got, id)
		}
		rows.Close()
		if !slices.Equal(got, order) {
			t.Fatalf("%s rows not written in source order", table)
		}
	}
}

func TestParallelAnalysisStopsAtCorruptRecord(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	writer := parallelTestSession(t, 200)
	if _, err := writer.db.Exec("UPDATE requests SET data=? WHERE id='tx-0100'", []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	rs, _ := rulesFromYAML(nil)
	done := make(chan error, 1)
	go func() {
		_, err := analyzeSessionRules(context.Background(), writer.dir, "", rs, time.Minute, 20)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("corrupt record accepted")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("analysis hung on a corrupt record")
	}
	if analysisExists(writer.dir) {
		t.Fatal("failed analysis published a generation")
	}
}

func TestParallelAnalysisCancels(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	writer := parallelTestSession(t, 300)
	rs, _ := rulesFromYAML(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := analyzeSessionRules(ctx, writer.dir, "", rs, time.Minute, 20); err == nil {
		t.Fatal("cancelled analysis succeeded")
	}
	if analysisExists(writer.dir) {
		t.Fatal("cancelled analysis published a generation")
	}
}

func TestAnalysisReportsScanLimit(t *testing.T) {
	writer := tuiTestStore(t)
	base := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	for i := range maxScanPaths + 10 {
		putTUITransaction(t, writer, Transaction{ID: fmt.Sprintf("p-%04d", i), Time: base.Add(time.Duration(i) * time.Millisecond), Client: "192.0.2.9:4000", Method: "GET", URL: fmt.Sprintf("/p/%d", i), Status: 404})
	}
	os.WriteFile(filepath.Join(writer.dir, "capture.lock"), nil, 0600)
	rs, _ := rulesFromYAML(nil)
	report, err := analyzeSessionRules(context.Background(), writer.dir, "", rs, time.Minute, 20)
	if err != nil {
		t.Fatal(err)
	}
	if report.ScanSkipped == nil || report.ScanSkipped.Paths != 10 || report.ScanSkipped.Clients != 0 {
		t.Fatalf("scan limit not reported: %+v", report.ScanSkipped)
	}
	stored, err := readAnalysisReport(writer.dir)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ScanSkipped == nil || *stored.ScanSkipped != *report.ScanSkipped {
		t.Fatalf("published report lost scan limit: %+v", stored.ScanSkipped)
	}
}
