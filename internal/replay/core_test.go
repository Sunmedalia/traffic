package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/tcpassembly"
	"golang.org/x/sync/semaphore"
)

func TestFrames(t *testing.T) {
	f := &Frames{}
	req := []byte("POST /api/echo HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nhello")
	for i, b := range req {
		frames, gap := f.feed("connection", []byte{b})
		if gap {
			t.Fatalf("gap at %d", i)
		}
		if i < len(req)-1 && len(frames) > 0 {
			t.Fatal("premature frame")
		}
		if i == len(req)-1 && (len(frames) != 1 || !bytes.Equal(frames[0], req)) {
			t.Fatal("frame mismatch")
		}
	}
}
func TestResponsePairing(t *testing.T) {
	s, e := openStore(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	p := newHTTP(s)
	for _, key := range []string{"a", "b"} {
		req := "GET / HTTP/1.1\r\nHost: test\r\n\r\n"
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
		if key == "b" {
			p.process(strings.NewReader(resp), key, "client", "test", 1, false)
		}
		p.process(strings.NewReader(req), key, "client", "test", 1, false)
		if key == "a" {
			p.process(strings.NewReader(resp), key, "client", "test", 1, false)
		}
	}
	rows, e := s.db.Query("SELECT " + storedRecord + " FROM requests")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var b []byte
		rows.Scan(&b)
		var x Transaction
		json.Unmarshal(b, &x)
		if x.Status != 200 || !bytes.HasSuffix(x.Response, []byte("ok")) {
			t.Fatalf("bad pair %+v", x)
		}
		count++
	}
	if count != 2 {
		t.Fatal(count)
	}
}
func TestOfflineQueueBackpressureAndCancellation(t *testing.T) {
	for _, cancelReplay := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancelReplay), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			// Each chunk exhausts the shared byte budget. Also constrain the
			// channel so either wait has to make progress.
			budget := semaphore.NewWeighted(2)
			q := &queuedStream{ctx: ctx, budget: budget, chunks: make(chan streamChunk, 1)}
			q.Reassembled([]tcpassembly.Reassembly{{Bytes: []byte("ab")}})
			done := make(chan struct{})
			go func() {
				q.Reassembled([]tcpassembly.Reassembly{{Bytes: []byte("cd")}})
				q.ReassemblyComplete()
				close(done)
			}()
			if cancelReplay {
				cancel()
				<-done
			}
			data, err := io.ReadAll(q)
			<-done
			want := "abcd"
			if cancelReplay {
				want = "ab"
			}
			if err != nil || string(data) != want || q.Incomplete() {
				t.Fatalf("got %q, incomplete=%t, err=%v, want %q", data, q.Incomplete(), err, want)
			}
			if !budget.TryAcquire(2) {
				t.Fatal("buffer accounting leak")
			}
		})
	}
}

func TestTruncatedEvidencePreserved(t *testing.T) {
	s, e := openStore(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	p := newHTTP(s)
	body := strings.Repeat("a", defaultRequestLimit+100)
	req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	p.process(strings.NewReader(req), "truncate", "client", "test", 1, false)
	row := storedRecords(t, s)["/"]
	if !row.Truncated || !bytes.Contains(row.Request, []byte("POST / HTTP/1.1")) || !bytes.HasSuffix(row.Request, []byte(strings.Repeat("a", defaultRequestLimit))) {
		t.Fatal("truncated evidence missing")
	}
}
func TestInterimResponse(t *testing.T) {
	s, e := openStore(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	p := newHTTP(s)
	p.process(strings.NewReader("GET / HTTP/1.1\r\nHost: test\r\n\r\n"), "interim", "client", "test", 1, false)
	p.process(strings.NewReader("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), "interim", "client", "test", 1, false)
	var b []byte
	s.db.QueryRow("SELECT " + storedRecord + " FROM requests").Scan(&b)
	var row Transaction
	json.Unmarshal(b, &row)
	if row.Status != 200 {
		t.Fatalf("wrong final status %d", row.Status)
	}
}

func TestPartialTLSExpiry(t *testing.T) {
	s, e := openStore(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	p := newHTTP(s)
	frames := &Frames{}
	frames.ingest("socket-read", []byte("POST /partial HTTP/1.1\r\nHost: test\r\nContent-Length: 100\r\n\r\nshort"), frameContext{connection: "socket", client: "192.0.2.1:1234", pid: 1}, false, p)
	var count int
	s.db.QueryRow("SELECT count(*) FROM requests").Scan(&count)
	if count != 0 {
		t.Fatal("unfinished frame emitted prematurely")
	}
	frames.expire(time.Now().Add(61*time.Second), false, p, "")
	var raw []byte
	if e = s.db.QueryRow("SELECT " + storedRecord + " FROM requests").Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var record Transaction
	json.Unmarshal(raw, &record)
	if !record.Incomplete || record.URL != "/partial" || !bytes.HasSuffix(record.Request, []byte("short")) {
		t.Fatalf("bad partial record %+v", record)
	}
	frames.expire(time.Now(), true, p, "")
	s.db.QueryRow("SELECT count(*) FROM requests").Scan(&count)
	if count != 1 {
		t.Fatal("partial frame emitted twice")
	}
}
func TestStorePathAndTimeOrdering(t *testing.T) {
	name := "case?mode=ro#evidence"
	if runtime.GOOS == "windows" {
		name = "case 空格%3fmode=ro#evidence"
	}
	dir := filepath.Join(t.TempDir(), name)
	s, e := openStore(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, nano := range []int{0, 1, 10} {
		if e = s.save(Transaction{ID: fmt.Sprint(i), Time: stamp.Add(time.Duration(nano)), Client: "test"}); e != nil {
			t.Fatal(e)
		}
	}
	rows, e := s.db.Query("SELECT id FROM requests ORDER BY time")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for i := 0; rows.Next(); i++ {
		var id string
		rows.Scan(&id)
		if id != fmt.Sprint(i) {
			t.Fatalf("timestamp ordering %q at %d", id, i)
		}
	}
}

// storedRecord selects a requests row as its full transaction JSON.
const storedRecord = "traffic_record_json(data,request_raw,response_raw,NULL)"
