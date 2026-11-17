package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBatchedIndexRestoresUncommittedRequest(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	stop := s.startIndexWriter(context.Background())
	defer stop()
	p := newHTTP(s)
	p.process(strings.NewReader("GET /batch HTTP/1.1\r\nHost: test\r\n\r\n"), "batch", "client", "test", 0, false)
	p.process(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), "batch", "client", "test", 0, false)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	records := readRecords(t, s)
	if len(records) != 1 || records["/batch"].Status != 200 || !strings.HasSuffix(string(records["/batch"].Response), "ok") {
		t.Fatal(records)
	}
	if s.stats.Transactions != 1 || s.stats.IndexPendingWrites != 0 {
		t.Fatal(s.stats)
	}
}
func TestBatchedIndexBoundAndFinalFlush(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	// Disable the timer in this case to exercise the exact count bound.
	s.indexBatching = true
	for i := 0; i < 64; i++ {
		if err := s.save(Transaction{ID: fmt.Sprint(i), Time: time.Now(), URL: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if s.indexTx != nil || s.stats.IndexPendingWrites != 0 {
		t.Fatal("batch did not commit at its bound")
	}
	if len(readRecords(t, s)) != 64 {
		t.Fatal("committed rows missing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop := s.startIndexWriter(ctx)
	cancel()
	if err := s.save(Transaction{ID: "late", Time: time.Now(), URL: "late"}); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if len(readRecords(t, s)) != 65 {
		t.Fatal("stop discarded a final partial record")
	}
}
func TestBatchedIndexCommitFailureIsVisible(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	s.indexBatching = true
	if err := s.save(Transaction{ID: "rollback", Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.indexTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := s.flushIndex(); err == nil {
		t.Fatal("failed transaction reported as committed")
	}
	if s.stats.GapCounts["index/commit_unconfirmed/writes"] != 1 {
		t.Fatal(s.stats)
	}
	if len(readRecords(t, s)) != 0 {
		t.Fatal("rolled back row appeared committed")
	}
}

func TestRetentionUsesActiveIndexBatch(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	s.indexBatching = true
	now := time.Now().UTC()
	for _, record := range []Transaction{
		{ID: "expired", Time: now.Add(-2 * time.Hour)},
		{ID: "recent", Time: now},
	} {
		if err := s.save(record); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- s.pruneIndex(now.Add(-time.Hour)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		// Release the connection before failing so the test cannot hang in Close.
		_ = s.indexTx.Rollback()
		<-done
		t.Fatal("retention waited for the connection held by its own batch")
	}
	if err := s.flushIndex(); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := s.db.QueryRow("SELECT id FROM requests").Scan(&id); err != nil || id != "recent" {
		t.Fatal("retention removed recent data or retained expired data", id, err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM requests").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestIndexBatchesPreserveBodyAndAlertHistory(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	s.indexBatching = true
	scanAlert := Alert{Rule: "SCAN-001"}
	requestAlert := Alert{Rule: "request-rule"}
	responseAlert := Alert{Rule: "response-rule"}
	body := []byte(strings.Repeat("large request body ", 8192))
	original := Transaction{ID: "paired", Time: time.Now(), Request: body, Alerts: []Alert{scanAlert, requestAlert}}
	if added, err := s.persist(original); err != nil || len(added) != 2 {
		t.Fatal("initial alerts", added, err)
	}
	if err := s.flushIndex(); err != nil {
		t.Fatal(err)
	}
	// A new batch must restore the committed request, then retain its scan
	// alert while deduplicating alerts already delivered for that request.
	restored := Transaction{ID: original.ID}
	if err := s.restore(&restored); err != nil {
		t.Fatal(err)
	}
	restored.Response = []byte("response")
	restored.Status = 200
	restored.Alerts = []Alert{requestAlert, responseAlert}
	if added, err := s.persist(restored); err != nil || len(added) != 1 || added[0] != responseAlert {
		t.Fatal("response alert deduplication", added, err)
	}
	// Restore before committing exercises the transaction-bound read statement.
	if err := s.restore(&restored); err != nil {
		t.Fatal(err)
	}
	if string(restored.Request) != string(body) || restored.Status != 200 || len(restored.Alerts) != 3 {
		t.Fatal("paired evidence or retained scan alert changed")
	}
	if err := s.flushIndex(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.persist(Transaction{ID: "next-batch", Time: time.Now()}); err != nil {
		t.Fatal("statement reused after its transaction closed", err)
	}
	if err := s.flushIndex(); err != nil {
		t.Fatal(err)
	}
	if s.stats.Transactions != 2 || s.stats.Alerts != 3 {
		t.Fatal("counters changed across batches", s.stats.Transactions, s.stats.Alerts)
	}
}
