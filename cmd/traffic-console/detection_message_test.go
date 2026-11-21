package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Sunmedalia/traffic/internal/session"
)

// referenceDetectionMessage is the original implementation, which always
// parsed the message a second time through DecodedBody.
func referenceDetectionMessage(raw []byte, response bool, limit int) detectionHTTP {
	message := detectionHTTP{raw: string(raw)}
	head, payload, found := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !found {
		head, payload, found = bytes.Cut(raw, []byte("\n\n"))
	}
	if found {
		_, headers, _ := bytes.Cut(head, []byte("\n"))
		message.headers, message.body = string(headers), string(payload)
	}
	reader := bufio.NewReaderSize(bytes.NewReader(raw), 4096)
	var body io.ReadCloser
	if response {
		parsed, err := http.ReadResponse(reader, nil)
		if err == nil {
			message.fields, body = parsed.Header, parsed.Body
		}
	} else {
		parsed, _, err := session.ReadRequest(reader)
		if err == nil {
			message.fields, body = parsed.Header, parsed.Body
			if parsed.Host != "" {
				message.fields.Set("Host", parsed.Host)
			}
		}
	}
	if body != nil {
		data, _ := io.ReadAll(io.LimitReader(body, int64(limit)))
		body.Close()
		message.body = string(data)
	}
	message.decoded, message.decodedView = session.DecodedBody(raw, limit)
	return message
}

func gzipped(text string) string {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write([]byte(text))
	w.Close()
	return out.String()
}

func chunked(body string) string {
	var out strings.Builder
	for len(body) > 0 {
		n := min(len(body), 7)
		fmt.Fprintf(&out, "%x\r\n%s\r\n", n, body[:n])
		body = body[n:]
	}
	return out.String() + "0\r\n\r\n"
}

// detectionCorpus covers parse failures, both header terminators, gzip in
// every framing, truncation and messages on the "wrong" side.
func detectionCorpus() [][]byte {
	attack := "q=1 union select 2&x=<script>alert(1)</script>&p=../../etc/passwd root:x:0:0:"
	z := gzipped(attack)
	var corpus []string
	for _, head := range []string{
		"GET /a?b=%zz HTTP/1.1\r\nHost: test\r\nUser-Agent: sqlmap/1.7\r\n",
		"POST /upload HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\n",
		"POST /upload HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\nContent-Encoding: gzip\r\n",
		"POST /upload HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nContent-Encoding: GZIP\r\n",
		"POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 2\r\nContent-Length: 3\r\n",
		"GET http://other/x HTTP/1.1\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Encoding: gzip\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n",
		"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n",
		"HTTP/1.0 404 Not Found\r\n",
		"not http at all\r\n",
	} {
		for _, body := range []string{"", attack, z} {
			framed := body
			if strings.Contains(head, "chunked") {
				framed = chunked(body)
			}
			h := head
			if strings.Contains(h, "%d") {
				h = fmt.Sprintf(h, len(framed))
			}
			for _, end := range []string{"\r\n", "\n"} {
				message := strings.ReplaceAll(h, "\r\n", end[:len(end)-1]+"\n") + end + framed
				corpus = append(corpus, message)
				// Truncated mid-body and mid-header.
				corpus = append(corpus, message[:len(message)-len(framed)/2], message[:len(h)/2])
			}
		}
	}
	corpus = append(corpus, "", "\r\n\r\n", "\n\n", "HTTP/", "GET / HTTP/1.1\r\nHost: a\n\r\nbody")
	r := rand.New(rand.NewSource(7))
	for range 300 {
		b := []byte(corpus[r.Intn(len(corpus))])
		if len(b) > 0 {
			b[r.Intn(len(b))] = byte(r.Intn(256))
		}
		corpus = append(corpus, string(b))
	}
	out := make([][]byte, len(corpus))
	for i, c := range corpus {
		out[i] = []byte(c)
	}
	return out
}

func TestDetectionMessageMatchesReference(t *testing.T) {
	views := map[string]int{}
	crossed := 0
	for i, raw := range detectionCorpus() {
		for _, response := range []bool{false, true} {
			for _, limit := range []int{8, 1 << 20} {
				got, want := detectionMessage(raw, response, limit), referenceDetectionMessage(raw, response, limit)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("message %d response=%v limit=%d %q:\ngot  %+v\nwant %+v", i, response, limit, raw, got, want)
				}
				views[want.decodedView]++
				if want.decoded != "" && response != bytes.HasPrefix(raw, []byte("HTTP/")) {
					crossed++
				}
			}
		}
	}
	// Every gzip outcome must occur, including bodies only DecodedBody's own
	// choice of parser can decode.
	for _, view := range []string{"gzip-body", "gzip-body-truncated", "gzip-body-incomplete"} {
		if views[view] == 0 {
			t.Fatalf("corpus never produced %s: %v", view, views)
		}
	}
	if crossed == 0 {
		t.Fatal("corpus never decoded a body through the other parser")
	}
}
