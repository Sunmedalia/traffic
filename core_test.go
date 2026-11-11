package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/tcpassembly"
)

func TestRules(t *testing.T) {
	if e := loadRules(""); e != nil {
		t.Fatal(e)
	}
	for _, x := range []struct {
		s    string
		want bool
	}{{"/search?q=union%20select%201", true}, {"/?q=hello", false}, {"/?q=%252e%252e%252f%252e%252e%252fetc/passwd", true}, {"/?q=hello;whoami", true}, {"/.env", true}, {"/?q=O'Reilly", false}} {
		if got := len(detect(Transaction{URL: x.s, Request: []byte(x.s)})) > 0; got != x.want {
			t.Errorf("%s got %v", x.s, got)
		}
	}
}
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
	loadRules("")
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
	rows, e := s.db.Query("SELECT data FROM requests")
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
func TestExport(t *testing.T) {
	loadRules("")
	s, e := openStore(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	os.WriteFile(filepath.Join(s.dir, "capture.lock"), nil, 0600)
	out := filepath.Join(t.TempDir(), "event.zip")
	x := Transaction{ID: "example", Time: time.Now(), Request: []byte("example")}
	b, _ := json.Marshal(x)
	if e = exportEvidence(s, x, b, out); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(out); e != nil {
		t.Fatal(e)
	}
	if e = exportEvidence(s, x, b, out); e == nil {
		t.Fatal("overwrote export")
	}
}
func TestProtobufMalformed(t *testing.T) {
	for _, b := range [][]byte{{255}, {10, 255}, {8, 255}} {
		if _, _, e := protoFields(b); e == nil {
			t.Fatal(fmt.Sprint(b))
		}
	}
}

func TestScan(t *testing.T) {
	scans.Lock()
	scans.clients = map[string]*scanState{}
	scans.Unlock()
	now := time.Now()
	for i := 0; i < 20; i++ {
		a := scan(Transaction{Time: now, Client: "192.0.2.1:1234", URL: fmt.Sprintf("/path-%d", i), Status: 404})
		if (a != nil) != (i == 19) {
			t.Fatalf("threshold at %d: %+v", i, a)
		}
	}
}
func TestLossyQueue(t *testing.T) {
	s, e := openStore(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	q := &queuedStream{chunks: make(chan []byte, 1), store: s}
	q.Reassembled([]tcpassembly.Reassembly{{Bytes: []byte("a")}, {Bytes: []byte("b")}})
	if !q.Incomplete() {
		t.Fatal("missing gap")
	}
	io.Copy(io.Discard, q)
	if queuedBytes.Load() != 0 {
		t.Fatal("buffer accounting leak")
	}
}

func TestTruncatedEvidencePreserved(t *testing.T) {
	loadRules("")
	s, e := openStore(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	p := newHTTP(s)
	body := strings.Repeat("a", requestLimit+100)
	req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	p.process(strings.NewReader(req), "truncate", "client", "test", 1, false)
	var b []byte
	s.db.QueryRow("SELECT data FROM requests").Scan(&b)
	var row Transaction
	json.Unmarshal(b, &row)
	if !row.Truncated || !bytes.Contains(row.Request, []byte("POST / HTTP/1.1")) || !bytes.HasSuffix(row.Request, []byte(strings.Repeat("a", requestLimit))) {
		t.Fatal("truncated evidence missing")
	}
}
func TestInterimResponse(t *testing.T) {
	loadRules("")
	s, e := openStore(t.TempDir(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	p := newHTTP(s)
	p.process(strings.NewReader("GET / HTTP/1.1\r\nHost: test\r\n\r\n"), "interim", "client", "test", 1, false)
	p.process(strings.NewReader("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), "interim", "client", "test", 1, false)
	var b []byte
	s.db.QueryRow("SELECT data FROM requests").Scan(&b)
	var row Transaction
	json.Unmarshal(b, &row)
	if row.Status != 200 {
		t.Fatalf("wrong final status %d", row.Status)
	}
}

func TestPartialTLSExpiry(t *testing.T) {
	loadRules("")
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
	if e = s.db.QueryRow("SELECT data FROM requests").Scan(&raw); e != nil {
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
func TestDropCountersAcrossInterfaces(t *testing.T) {
	s := &Store{}
	s.recordPacketDrops("eth0", 3)
	s.recordPacketDrops("lo", 4)
	s.recordPacketDrops("eth0", 5)
	if s.stats.Dropped != 9 {
		t.Fatalf("lost interface count: %d", s.stats.Dropped)
	}
}

func TestDecodeProvenance(t *testing.T) {
	loadRules("")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Write([]byte("union select 1"))
	writer.Close()
	payload := append([]byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", compressed.Len())), compressed.Bytes()...)
	alerts := detect(Transaction{Request: payload})
	if len(alerts) == 0 || alerts[0].View != "gzip-body" {
		t.Fatalf("missing gzip provenance %+v", alerts)
	}
	alerts = detect(Transaction{Request: []byte("GET /?q=%75nion%20select%201 HTTP/1.1\r\nHost: test\r\nX-Literal-Percent: %\r\n\r\n")})
	if len(alerts) == 0 || alerts[0].Decoding != 1 {
		t.Fatalf("valid escapes hidden by invalid escape %+v", alerts)
	}
}

func TestStorePathAndTimeOrdering(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "case?mode=ro#evidence")
	s, e := openStore(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	loadRules("")
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
