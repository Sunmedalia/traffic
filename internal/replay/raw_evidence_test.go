package replay

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
)

// Attack and scanner requests that net/http rejects must stay in the
// evidence, keep the connection's later requests, and pair with their own
// responses. Saved messages are the original bytes, not a re-serialisation.
func TestMalformedRequestsKeepConnectionAndRawBytes(t *testing.T) {
	requests := [][]byte{
		[]byte("GET /..%c0%af../%zz?q=%u002e HTTP/1.1\r\nhost: victim\r\nX-Probe:\x01\r\nBad Header: x\r\n\r\n"),
		[]byte("POST /upload HTTP/1.1\r\nHost: victim\r\nContent-Length: 4\r\nContent-Length: 6\r\n\r\nabcd"),
		[]byte("POST /chunk HTTP/1.1\nHost: victim\ntransfer-encoding: chunked\n\n3\r\nabc\r\n0\r\nX-Trailer: t\r\n\r\n"),
		[]byte("GET http://evil.example/next HTTP/1.1\r\nHost: victim\r\nuser-agent: () { :; }; /bin/id\r\nx-forwarded-for: 198.51.100.7\r\n\r\n"),
	}
	responses := [][]byte{
		[]byte("HTTP/1.1 400 Bad Request\r\ncontent-length: 3\r\nX-B: 2\r\nX-A: 1\r\n\r\nbad"),
		[]byte("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"),
		[]byte("HTTP/1.1 204 No Content\r\n\r\n"),
	}
	input, write, closePCAP := writeReplayPCAP(t)
	at := time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC)
	write(at, 41000, false, 100, true, nil)
	write(at, 41000, true, 500, true, nil)
	clientSeq, serverSeq := uint32(101), uint32(501)
	for i := range requests {
		at = at.Add(time.Millisecond)
		write(at, 41000, false, clientSeq, false, requests[i])
		clientSeq += uint32(len(requests[i]))
		write(at, 41000, true, serverSeq, false, responses[i])
		serverSeq += uint32(len(responses[i]))
	}
	closePCAP()
	records, gaps := replayTestPCAP(t, input)
	for key := range gaps {
		if strings.Contains(key, "parse_failure") || strings.Contains(key, "midstream") {
			t.Fatalf("unexpected gap %s: %v", key, gaps)
		}
	}
	if len(records) != len(requests) {
		t.Fatalf("got %d records, want %d: %+v", len(records), len(requests), records)
	}
	wantStatus := []int{400, 201, 200, 204}
	wantReasons := [][]string{{"lenient_request_parse", "malformed_header_line"}, {"lenient_request_parse", "ambiguous_content_length"}, nil, nil}
	for i, record := range records {
		if !bytes.Equal(record.Request, requests[i]) {
			t.Errorf("request %d saved as %q, want original %q", i, record.Request, requests[i])
		}
		if !bytes.Equal(record.Response, responses[i]) {
			t.Errorf("response %d saved as %q, want original %q", i, record.Response, responses[i])
		}
		if record.Status != wantStatus[i] || record.Incomplete || record.Truncated {
			t.Errorf("record %d status=%d incomplete=%t truncated=%t", i, record.Status, record.Incomplete, record.Truncated)
		}
		for _, reason := range wantReasons[i] {
			if !slices.Contains(record.IntegrityReasons, reason) {
				t.Errorf("record %d reasons %v lack %s", i, record.IntegrityReasons, reason)
			}
		}
	}
	if records[0].URL != "/..%c0%af../%zz?q=%u002e" || records[0].Method != "GET" || records[0].Host != "victim" {
		t.Errorf("malformed request fields %+v", records[0])
	}
	// RFC 9112 3.2.2: the absolute-form authority wins for analysis, while
	// the saved bytes (checked above) still carry the client's Host header.
	if records[3].Host != "evil.example" {
		t.Errorf("absolute-form host %q", records[3].Host)
	}
}

// A malformed request inside TLS plaintext must still be framed so the next
// message on the connection is not dropped.
func TestTLSFramesKeepMalformedRequest(t *testing.T) {
	f := &Frames{}
	first := []byte("GET /%zz HTTP/1.1\r\nHost: test\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nab")
	second := []byte("GET /next HTTP/1.1\r\nHost: test\r\n\r\n")
	frames, gap := f.feed("connection", append(append([]byte(nil), first...), second...))
	if gap || len(frames) != 2 || !bytes.Equal(frames[0], first) || !bytes.Equal(frames[1], second) {
		t.Fatalf("gap=%t frames=%q", gap, frames)
	}
}
