package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func readRecords(t *testing.T, s *Store) map[string]Transaction {
	t.Helper()
	rows, err := s.db.Query("SELECT data FROM requests")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]Transaction{}
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		var record Transaction
		if err := json.Unmarshal(b, &record); err != nil {
			t.Fatal(err)
		}
		out[record.URL] = record
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestFrameEvictionIsLocalAndAccounted(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	f := &Frames{byteLimit: 128, connectionLimit: 2}
	meta := func(key string) frameContext {
		return frameContext{connection: key, client: "127.0.0.1:1234", first: time.Now().UTC()}
	}
	f.ingest("a-read", []byte("GET /a HTTP/1.1\r\nHost: a\r\nX:"), meta("a"), false, p)
	f.ingest("b-read", []byte("GET /b HTTP/1.1\r\nHost: b\r\nX:"), meta("b"), false, p)
	f.ingest("c-read", []byte("GET /c HTTP/1.1\r\nHost: c\r\nX:"), meta("c"), false, p)
	if f.buffers["a-read"] != nil || len(f.buffers["b-read"]) == 0 || len(f.buffers["c-read"]) == 0 {
		t.Fatal("eviction affected unrelated connections")
	}
	total := 0
	for _, b := range f.buffers {
		total += len(b)
	}
	if f.buffered != total {
		t.Fatalf("accounting %d != %d", f.buffered, total)
	}
	f.ingest("b-read", []byte(" yes\r\n\r\n"), meta("b"), false, p)
	records := readRecords(t, s)
	if records["/b"].Incomplete {
		t.Fatal("unrelated request marked incomplete")
	}
	if s.stats.GapCounts["tls/buffer_evicted/connections"] != 1 {
		t.Fatal(s.stats)
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "gaps.jsonl"))
	if err != nil || !bytes.Contains(b, []byte("buffer_evicted")) {
		t.Fatal("gap journal missing", err)
	}
}
func TestGapCannotPairAcrossBoundary(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	p.process(strings.NewReader("GET /before HTTP/1.1\r\nHost: test\r\n\r\n"), "one", "client", "test", 0, false)
	p.invalidate("one", "test_gap")
	p.process(strings.NewReader("GET /after HTTP/1.1\r\nHost: test\r\n\r\n"), "one", "client", "test", 0, false)
	p.process(strings.NewReader("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"), "one", "client", "test", 0, false)
	rows := readRecords(t, s)
	if rows["/before"].Status != 0 || !rows["/before"].Incomplete || rows["/after"].Status != 201 {
		t.Fatal(rows)
	}
}
func h2Headers(t *testing.T, encoder *hpack.Encoder, block *bytes.Buffer, framer *http2.Framer, id uint32, end bool, fields ...hpack.HeaderField) {
	t.Helper()
	block.Reset()
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: end}); err != nil {
		t.Fatal(err)
	}
}
func TestHTTP2MultiplexingHPACKAndTruncation(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	var requests, responses, block bytes.Buffer
	requests.WriteString(h2Preface)
	req := http2.NewFramer(&requests, nil)
	resp := http2.NewFramer(&responses, nil)
	req.WriteSettings()
	resp.WriteSettings()
	encoder := hpack.NewEncoder(&block)
	h2Headers(t, encoder, &block, req, 1, true, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: "/one"}, hpack.HeaderField{Name: ":authority", Value: "test"}, hpack.HeaderField{Name: "x-test", Value: "shared-table-value"})
	h2Headers(t, encoder, &block, req, 3, true, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: "/three"}, hpack.HeaderField{Name: ":authority", Value: "test"}, hpack.HeaderField{Name: "x-test", Value: "shared-table-value"})
	encoder = hpack.NewEncoder(&block)
	h2Headers(t, encoder, &block, resp, 3, false, hpack.HeaderField{Name: ":status", Value: "201"})
	resp.WriteData(3, true, []byte("three"))
	h2Headers(t, encoder, &block, resp, 1, false, hpack.HeaderField{Name: ":status", Value: "200"})
	resp.WriteData(1, false, bytes.Repeat([]byte("x"), responseLimit))
	resp.WriteData(1, true, []byte("discarded"))
	p.process(bytes.NewReader(requests.Bytes()), "h2", "127.0.0.1:1234", "test", 0, false)
	p.process(bytes.NewReader(responses.Bytes()), "h2", "127.0.0.1:443", "test", 0, false)
	p.finish()
	rows := readRecords(t, s)
	if len(rows) != 2 || rows["/one"].Status != 200 || !rows["/one"].Truncated || rows["/one"].Incomplete || rows["/three"].Status != 201 || !bytes.HasSuffix(rows["/three"].Response, []byte("three")) {
		t.Fatalf("bad multiplexing: %+v", rows)
	}
	if rows["/one"].StreamID != 1 || rows["/three"].StreamID != 3 || rows["/one"].Protocol != "HTTP/2.0" {
		t.Fatal(rows)
	}
	if p.h2bytes != 0 {
		t.Fatalf("HTTP/2 leaked accounting: %d", p.h2bytes)
	}
}
func TestHTTP2HookByteFragments(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	frames := &Frames{}
	var wire, block bytes.Buffer
	wire.WriteString(h2Preface)
	framer := http2.NewFramer(&wire, nil)
	framer.WriteSettings()
	h2Headers(t, hpack.NewEncoder(&block), &block, framer, 1, true, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: "/fragmented"})
	meta := frameContext{connection: "hook", client: "127.0.0.1:5000", local: "127.0.0.1:443"}
	for _, b := range wire.Bytes() {
		frames.ingest("hookread", []byte{b}, meta, false, p)
	}
	rows := readRecords(t, s)
	if len(rows) != 1 || rows["/fragmented"].Protocol != "HTTP/2.0" {
		t.Fatalf("rows=%+v stats=%+v h2=%+v protocols=%+v", rows, s.stats, p.h2, frames.http2)
	}
	frames.expire(time.Now(), true, p, "")
	p.finish()
	if p.h2bytes != 0 {
		t.Fatal("accounting after expiry", p.h2bytes)
	}
}
func TestHTTP2MissingHPACKHistoryFailsExplicitly(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	var wire bytes.Buffer
	wire.WriteString(h2Preface)
	f := http2.NewFramer(&wire, nil)
	f.WriteSettings()
	f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: true, BlockFragment: []byte{0xff, 0x7f}})
	p.process(bytes.NewReader(wire.Bytes()), "missing", "client", "test", 0, false)
	if s.stats.GapCounts["http2/http2_hpack_unrecoverable/connections"] != 1 {
		t.Fatal(s.stats)
	}
	if len(readRecords(t, s)) != 0 {
		t.Fatal("invented headers from missing history")
	}
}
func TestPreflightStrictFailure(t *testing.T) {
	if requireCaptureChecks(nil) == nil || requireCaptureChecks([]captureCheck{{Status: "unavailable"}}) == nil {
		t.Fatal("strict preflight accepted unsupported target")
	}
	if err := requireCaptureChecks([]captureCheck{{Status: "candidate"}}); err != nil {
		t.Fatal(err)
	}
}

func TestTLSLargeBodyDrainsBeforeNextRequest(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	frames := &Frames{}
	body := strings.Repeat("x", requestLimit*3)
	wire := []byte(fmt.Sprintf("POST /large HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n\r\n%sGET /next HTTP/1.1\r\nHost: test\r\n\r\n", len(body), body))
	meta := frameContext{connection: "large", client: "127.0.0.1:1234", local: "127.0.0.1:443"}
	for len(wire) > 0 {
		n := min(16000, len(wire))
		frames.ingest("largeread", wire[:n], meta, false, p)
		wire = wire[n:]
	}
	rows := readRecords(t, s)
	if len(rows) != 2 || !rows["/large"].Truncated || rows["/large"].Incomplete || rows["/next"].Incomplete {
		t.Fatalf("lost boundary after truncated body: %+v", rows)
	}
	if frames.buffered != 0 || len(frames.drains) != 0 {
		t.Fatal("drain retained data", frames.buffered)
	}
}

func TestOversizedFragmentDoesNotEvictOtherConnections(t *testing.T) {
	f := &Frames{byteLimit: 64}
	f.feed("good", []byte("GET / HTTP/1.1\r\nHost:"))
	f.feed("bad", bytes.Repeat([]byte("x"), 65))
	if len(f.buffers["good"]) == 0 {
		t.Fatal("oversized event destroyed unrelated evidence")
	}
}
func TestHTTP2ResetAndContinuation(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	var wire, block bytes.Buffer
	wire.WriteString(h2Preface)
	f := http2.NewFramer(&wire, nil)
	f.WriteSettings()
	e := hpack.NewEncoder(&block)
	e.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	e.WriteField(hpack.HeaderField{Name: ":path", Value: "/reset"})
	cut := block.Len() / 2
	f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes()[:cut], EndHeaders: false})
	f.WriteContinuation(1, true, block.Bytes()[cut:])
	f.WriteData(1, false, []byte("partial"))
	f.WriteRSTStream(1, http2.ErrCodeCancel)
	p.process(bytes.NewReader(wire.Bytes()), "reset", "client", "test", 0, false)
	p.finish()
	rows := readRecords(t, s)
	if len(rows) != 1 || !rows["/reset"].Incomplete || !bytes.HasSuffix(rows["/reset"].Request, []byte("partial")) {
		t.Fatal(rows)
	}
	if p.h2bytes != 0 {
		t.Fatal("reset leaked buffers", p.h2bytes)
	}
}

func TestTLSHeadThenGetInSameRead(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	frames := &Frames{}
	meta := frameContext{connection: "pipeline", client: "127.0.0.1:1234", local: "127.0.0.1:443"}
	frames.ingest("pipelineread", []byte("HEAD /head HTTP/1.1\r\nHost: test\r\n\r\nGET /get HTTP/1.1\r\nHost: test\r\n\r\n"), meta, false, p)
	frames.ingest("pipelinewrite", []byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"), meta, true, p)
	rows := readRecords(t, s)
	if rows["/head"].Status != 200 || rows["/get"].Status != 201 || !bytes.HasSuffix(rows["/get"].Response, []byte("ok")) || rows["/get"].Incomplete {
		t.Fatal(rows)
	}
}

func TestHTTP2TrailersSurviveSave(t *testing.T) {
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	p := newHTTP(s)
	var request, response, block bytes.Buffer
	request.WriteString(h2Preface)
	f := http2.NewFramer(&request, nil)
	f.WriteSettings()
	encoder := hpack.NewEncoder(&block)
	h2Headers(t, encoder, &block, f, 1, true, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":path", Value: "/trailers"})
	f = http2.NewFramer(&response, nil)
	f.WriteSettings()
	encoder = hpack.NewEncoder(&block)
	h2Headers(t, encoder, &block, f, 1, false, hpack.HeaderField{Name: ":status", Value: "200"})
	f.WriteData(1, false, []byte("body"))
	h2Headers(t, encoder, &block, f, 1, true, hpack.HeaderField{Name: "x-checksum", Value: "evidence"})
	p.process(bytes.NewReader(request.Bytes()), "trailers", "client", "test", 0, false)
	p.process(bytes.NewReader(response.Bytes()), "trailers", "server", "test", 0, false)
	record := readRecords(t, s)["/trailers"]
	if record.Incomplete || record.ResponseTrailers["x-checksum"][0] != "evidence" || !bytes.HasSuffix(record.Response, []byte("body")) {
		t.Fatal(record)
	}
}

func TestProbeCapabilitiesRequireMatchingBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ecapture")
	binary := []byte("synthetic capability fixture")
	if err := os.WriteFile(path, binary, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	metadata := fmt.Sprintf(`{"schema_version":1,"sha256":"%s","openssl_abis":["1.1.1"],"features":["pid_scope_v1"]}`, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(path+".traffic.json", []byte(metadata), 0600); err != nil {
		t.Fatal(err)
	}
	if !probeCapability(path, "1.1.1") || probeCapability(path, "3.5") {
		t.Fatal("capability filtering failed")
	}
	if !probeCapability(path, "feature:pid_scope_v1") || probeCapability(path, "feature:missing") {
		t.Fatal("feature manifest filtering failed")
	}
	if err := os.WriteFile(path, []byte("replaced binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if probeCapability(path, "1.1.1") {
		t.Fatal("stale manifest accepted a replacement binary")
	}
	if probeCapability(path, "feature:pid_scope_v1") {
		t.Fatal("stale manifest enabled kernel filtering for a replacement binary")
	}
}

func TestOpenSSL111VersionIdentification(t *testing.T) {
	for text, want := range map[string]bool{"OpenSSL 1.1.1w 11 Sep 2023": true, "OpenSSL 1.1.1a vendor": true, "OpenSSL 1.1.0l": false, "OpenSSL 1.1.1 without an ABI suffix": false, "OpenSSL 1.1.1x vendor": false} {
		if openssl111Version.MatchString(text) != want {
			t.Fatal("wrong ABI classification", text)
		}
	}
}
