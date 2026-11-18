package session

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func readAll(t *testing.T, br *bufio.Reader) (string, string, []string, string) {
	t.Helper()
	request, reasons, err := ReadRequest(br)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err = request.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return request.Method, request.RequestURI, reasons, string(body)
}

func TestReadRequestKeepsPipelineAfterMalformedRequests(t *testing.T) {
	stream := "GET /%zz HTTP/1.1\r\nHost: a\r\nBad Header: 1\r\n\r\n" +
		"POST /dup HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabc" +
		"POST /te HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\nContent-Length: 99\r\n\r\n2\r\nhi\r\n0\r\nT: 1\r\n\r\n" +
		"GET /a\x01b HTTP/1.1\nHost: a\n\n" +
		"BROKEN-LINE\r\nHost: a\r\n\r\n" +
		"GET /ok HTTP/1.1\r\nHost: a\r\n\r\n"
	br := bufio.NewReaderSize(strings.NewReader(stream), 4096)
	want := []struct {
		method, uri, body string
		reasons           []string
	}{
		{"GET", "/%zz", "", []string{ReasonLenientRequest, ReasonMalformedHeaderLine}},
		{"POST", "/dup", "abc", []string{ReasonLenientRequest, ReasonAmbiguousLength}},
		{"POST", "/te", "hi", []string{ReasonLenientRequest, ReasonConflictingFraming}},
		{"GET", "/a\x01b", "", []string{ReasonLenientRequest}},
		{"BROKEN-LINE", "", "", []string{ReasonLenientRequest, ReasonMalformedRequestLine}},
		{"GET", "/ok", "", nil},
	}
	for i, expected := range want {
		method, uri, reasons, body := readAll(t, br)
		if method != expected.method || uri != expected.uri || body != expected.body || !slices.Equal(reasons, expected.reasons) {
			t.Fatalf("request %d = %q %q body %q reasons %v; want %+v", i, method, uri, body, reasons, expected)
		}
	}
	if _, _, err := ReadRequest(br); err != io.EOF {
		t.Fatalf("after pipeline: %v", err)
	}
}

func TestReadRequestStrictFieldsUnchanged(t *testing.T) {
	raw := "POST /x?a=1 HTTP/1.1\r\nhost: h\r\nContent-Length: 2\r\nX-Forwarded-For: 192.0.2.9\r\n\r\nokNEXT"
	br := bufio.NewReader(strings.NewReader(raw))
	request, reasons, err := ReadRequest(br)
	if err != nil || reasons != nil {
		t.Fatalf("strict request: %v %v", reasons, err)
	}
	body, _ := io.ReadAll(request.Body)
	request.Body.Close()
	rest, _ := io.ReadAll(br)
	if request.Host != "h" || request.URL.Query().Get("a") != "1" || request.Header.Get("X-Forwarded-For") != "192.0.2.9" || string(body) != "ok" || string(rest) != "NEXT" {
		t.Fatalf("host=%q url=%v body=%q rest=%q", request.Host, request.URL, body, rest)
	}
}

func TestReadRequestClosingUnreadBodyAdvances(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("POST /%zz HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /n HTTP/1.1\r\n\r\n"))
	request, _, err := ReadRequest(br)
	if err != nil {
		t.Fatal(err)
	}
	if err = request.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, uri, _, _ := readAll(t, br); uri != "/n" {
		t.Fatalf("next request %q", uri)
	}
}

func TestReadRequestIncompleteHeaderStaysAnError(t *testing.T) {
	if _, _, err := ReadRequest(bufio.NewReader(strings.NewReader("GET /%zz HTTP/1.1\r\nHost: a\r\n"))); err == nil {
		t.Fatal("partial header accepted")
	}
}

func TestDecodedBodyOfMalformedGzipRequest(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Write([]byte("union select 1"))
	writer.Close()
	raw := append([]byte("POST /%zz HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: "+strconv.Itoa(compressed.Len())+"\r\n\r\n"), compressed.Bytes()...)
	if text, view := DecodedBody(raw, 1024); text != "union select 1" || view != "gzip-body" {
		t.Fatalf("decoded %q view %q", text, view)
	}
}

func TestHeaderBlockLength(t *testing.T) {
	for input, want := range map[string]int{"GET / HTTP/1.1\r\n\r\nX": 18, "GET /\n\nX": 7, "GET /\nA: b\r\n\r\n": 14, "GET /\r\nA: b\r\n": -1} {
		if got := HeaderBlockLength([]byte(input)); got != want {
			t.Fatalf("%q => %d, want %d", input, got, want)
		}
	}
}

func TestReadRequestShortBodyIsUnexpectedEOF(t *testing.T) {
	for _, raw := range []string{"POST /%zz HTTP/1.1\r\nContent-Length: 9\r\n\r\nabc", "POST /ok HTTP/1.1\r\nContent-Length: 9\r\n\r\nabc", "POST /%zz HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab"} {
		request, _, err := ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(io.Discard, request.Body); err != io.ErrUnexpectedEOF {
			t.Fatalf("%q short body: %v", raw, err)
		}
	}
}
