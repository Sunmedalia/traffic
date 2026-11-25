package replay

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func countRows(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM requests").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Each request is parked without a copy, taken back once, and spilled to
// SQLite when the byte or entry bound evicts it.
func TestRequestCacheParksTakesAndSpills(t *testing.T) {
	var spilled []string
	spill := func(t Transaction) error { spilled = append(spilled, t.ID); return nil }
	c := requestCache{budget: 4096}
	body := bytes.Repeat([]byte("x"), 1400)
	for _, id := range []string{"a", "b", "c"} {
		if err := c.park(Transaction{ID: id, Method: "POST", Request: body}, spill); err != nil {
			t.Fatal(err)
		}
	}
	if c.bytes > 4096 || c.order.Len() != 1 || strings.Join(spilled, ",") != "a,b" {
		t.Fatal("cache exceeded budget or spilled out of order", c.bytes, c.order.Len(), spilled)
	}
	got, ok := c.take("c")
	if !ok || &got.Request[0] != &body[0] {
		t.Fatal("take did not hand the parked buffers back")
	}
	if _, ok := c.take("c"); ok || c.bytes != 0 || len(c.items) != 0 {
		t.Fatal("take left the request parked", c.bytes)
	}

	spilled = nil
	c = requestCache{entries: 2}
	for i := range 5 {
		_ = c.park(Transaction{ID: fmt.Sprint(i), Method: "GET"}, spill)
	}
	if c.order.Len() != 2 || strings.Join(spilled, ",") != "0,1,2" {
		t.Fatal("entry bound", c.order.Len(), spilled)
	}

	spilled = nil
	c = requestCache{budget: 2048}
	if err := c.park(Transaction{ID: "huge", Method: "POST", Request: bytes.Repeat([]byte("y"), 4096)}, spill); err != nil {
		t.Fatal(err)
	}
	if c.order.Len() != 0 || c.bytes != 0 || strings.Join(spilled, ",") != "huge" {
		t.Fatal("oversized request was parked", spilled)
	}
}

// A request that waits for its response is written to SQLite once, together
// with that response, and only when the pair completes.
func TestPendingRequestWrittenOnceWithResponse(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	p.process(strings.NewReader("POST /once HTTP/1.1\r\nHost: test\r\nContent-Length: 6\r\n\r\nneedle"), "once", "client", "test", 0, false)
	if n := countRows(t, s); n != 0 || s.stats.Transactions != 0 {
		t.Fatal("unpaired request written before its response", n)
	}
	p.process(strings.NewReader("HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"), "once", "client", "test", 0, false)
	records := readRecords(t, s)
	got := records["/once"]
	if len(records) != 1 || got.Status != 201 || !bytes.HasSuffix(got.Request, []byte("needle")) || !bytes.HasSuffix(got.Response, []byte("ok")) || got.Incomplete {
		t.Fatalf("bad pair %+v", got)
	}
	if s.stats.Transactions != 1 || s.requests.order.Len() != 0 {
		t.Fatal("pair counted twice or left parked", s.stats.Transactions, s.requests.order.Len())
	}
}

// Eviction must not lose evidence: a spilled request is restored from the
// uncommitted batch and rewritten with its response, counted once.
func TestEvictedPendingRequestPairsFromSQLite(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	s.indexBatching = true
	s.requests.entries = 1
	p := newHTTP(s)
	for _, key := range []string{"first", "second"} {
		p.process(strings.NewReader("GET /"+key+" HTTP/1.1\r\nHost: test\r\nX-Trace: "+key+"\r\n\r\n"), key, "client", "test", 0, false)
	}
	// The batch holds the only connection; count its writes instead.
	if s.indexOps != 1 {
		t.Fatal("eviction did not spill the oldest request", s.indexOps)
	}
	for _, key := range []string{"first", "second"} {
		p.process(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), key, "client", "test", 0, false)
	}
	if err := s.flushIndex(); err != nil {
		t.Fatal(err)
	}
	records := readRecords(t, s)
	for _, key := range []string{"first", "second"} {
		got := records["/"+key]
		if got.Status != 200 || !bytes.Contains(got.Request, []byte("X-Trace: "+key)) || got.Incomplete {
			t.Fatalf("%s lost evidence after eviction: %+v", key, got)
		}
	}
	if len(records) != 2 || s.stats.Transactions != 2 || s.fatal != nil {
		t.Fatal("spilled request duplicated or miscounted", len(records), s.stats.Transactions, s.fatal)
	}
}

// finish() and invalidate() persist parked requests as incomplete evidence.
func TestParkedRequestsPersistOnFinishAndInvalidate(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	p.process(strings.NewReader("GET /dropped HTTP/1.1\r\nHost: test\r\n\r\n"), "dropped", "client", "test", 0, false)
	p.process(strings.NewReader("GET /stopped HTTP/1.1\r\nHost: test\r\n\r\n"), "stopped", "client", "test", 0, false)
	p.invalidate("dropped", "tcp_stream_gap")
	if n := countRows(t, s); n != 1 {
		t.Fatal("invalidate did not persist its request", n)
	}
	p.finish()
	records := readRecords(t, s)
	if !records["/dropped"].Incomplete || !strings.Contains(strings.Join(records["/dropped"].IntegrityReasons, ","), "tcp_stream_gap") {
		t.Fatalf("invalidated request %+v", records["/dropped"])
	}
	if !records["/stopped"].Incomplete || !strings.Contains(strings.Join(records["/stopped"].IntegrityReasons, ","), "response_unfinished_at_stop") {
		t.Fatalf("unfinished request %+v", records["/stopped"])
	}
	if len(records) != 2 || s.stats.Transactions != 2 || s.requests.order.Len() != 0 || s.requests.bytes != 0 {
		t.Fatal("requests left parked after finish", len(records), s.stats.Transactions, s.requests.order.Len())
	}
}

// A loss reason recorded at request time must not also gain the generic
// stream_incomplete reason, as it did not before requests were parked.
func TestPairingLossKeepsSingleIntegrityReason(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	p.mu.Lock()
	p.loseHTTP1PairingLocked("lost", "pipeline_limit")
	p.mu.Unlock()
	p.process(strings.NewReader("GET /lost HTTP/1.1\r\nHost: test\r\n\r\n"), "lost", "client", "test", 0, false)
	got := readRecords(t, s)["/lost"]
	if strings.Join(got.IntegrityReasons, ",") != "pipeline_limit" || !got.Incomplete {
		t.Fatalf("reasons %v", got.IntegrityReasons)
	}
}

// Many connections pair concurrently while a tiny cache forces spills; every
// request must be written exactly once with its own response.
func TestConcurrentPairingWithSpills(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	stop := s.startIndexWriter(context.Background())
	defer stop()
	s.requests.entries = 3
	p := newHTTP(s)
	const workers, rounds = 8, 25
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := fmt.Sprint("conn-", w)
			for i := range rounds {
				p.process(strings.NewReader(fmt.Sprintf("GET /%d/%d HTTP/1.1\r\nHost: test\r\n\r\n", w, i)), key, "client", "test", 0, false)
				body := fmt.Sprintf("%d/%d", w, i)
				p.process(strings.NewReader(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)), key, "client", "test", 0, false)
			}
		}()
	}
	wg.Wait()
	p.finish()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	records := readRecords(t, s)
	if len(records) != workers*rounds || s.stats.Transactions != workers*rounds || s.fatal != nil {
		t.Fatal("concurrent pairs lost or duplicated", len(records), s.stats.Transactions, s.fatal)
	}
	for url, record := range records {
		if record.Status != 200 || !bytes.HasSuffix(record.Response, []byte(strings.TrimPrefix(url, "/"))) || record.Incomplete {
			t.Fatalf("%s paired with the wrong response: %q", url, record.Response)
		}
	}
}

// storedRecords returns what SQLite holds plus the requests parked for a
// response, keyed by URL, as finish() would persist them minus its reasons.
func storedRecords(t *testing.T, s *Store) map[string]Transaction {
	t.Helper()
	out := readRecords(t, s)
	s.requests.mu.Lock()
	defer s.requests.mu.Unlock()
	for e := s.requests.order.Front(); e != nil; e = e.Next() {
		record := e.Value.(requestCacheEntry).record
		out[record.URL] = record
	}
	return out
}
