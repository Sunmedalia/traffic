package session

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
)

// Integrity reasons attached to requests that net/http rejects. Attack and
// scanner traffic is often exactly what the strict parser refuses (invalid
// percent escapes, control bytes, duplicate Content-Length), so these requests
// are kept with a lenient reading instead of being discarded.
const (
	ReasonLenientRequest        = "lenient_request_parse"
	ReasonMalformedRequestLine  = "malformed_request_line"
	ReasonMalformedHeaderLine   = "malformed_header_line"
	ReasonAmbiguousLength       = "ambiguous_content_length"
	ReasonInvalidLength         = "invalid_content_length"
	ReasonConflictingFraming    = "conflicting_transfer_framing"
	maxLenientHeaderBlockLength = 1 << 20
)

// HeaderBlockLength returns the length of the header block at the start of b,
// including the terminating empty line, or -1 when b holds no complete block.
func HeaderBlockLength(b []byte) int {
	end := -1
	if i := bytes.Index(b, []byte("\n\r\n")); i >= 0 {
		end = i + 3
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 && (end < 0 || i+2 < end) {
		end = i + 2
	}
	return end
}

// ReadRequest reads one HTTP/1 request from br like http.ReadRequest. When
// the whole header block is already buffered and net/http rejects it, the
// request is read leniently instead and the returned reasons say why. Body
// framing is taken from the parsed header in both cases, and closing the body
// consumes the rest of the message, so the next request starts correctly.
func ReadRequest(br *bufio.Reader) (*http.Request, []string, error) {
	// Buffer the header block as http.ReadRequest would read it anyway.
	buffered, _ := br.Peek(br.Buffered())
	length := HeaderBlockLength(buffered)
	for length < 0 && br.Buffered() < br.Size() {
		if _, err := br.Peek(br.Buffered() + 1); err != nil {
			break
		}
		buffered, _ = br.Peek(br.Buffered())
		length = HeaderBlockLength(buffered)
	}
	if length < 0 {
		// The header is not buffered (or does not end): keep the strict
		// parser, which reads and reports exactly as before.
		request, err := http.ReadRequest(br)
		return request, nil, err
	}
	head := bytes.Clone(buffered[:length])
	if _, err := br.Discard(length); err != nil {
		return nil, nil, err
	}
	return requestFromHead(head, br)
}

// ParseRequest reads a saved request leniently. Detection and display use it
// so saved malformed requests keep their header fields and decoded body.
func ParseRequest(raw []byte) (*http.Request, []string, error) {
	length := HeaderBlockLength(raw)
	if length < 0 {
		request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		return request, nil, err
	}
	return requestFromHead(raw[:length], bufio.NewReader(bytes.NewReader(raw[length:])))
}

func requestFromHead(head []byte, body *bufio.Reader) (*http.Request, []string, error) {
	request, err := http.ReadRequest(bufio.NewReaderSize(bytes.NewReader(head), len(head)))
	var reasons []string
	if err != nil {
		if len(head) > maxLenientHeaderBlockLength {
			return nil, nil, err
		}
		request, reasons = lenientRequestHead(head)
	}
	chunked := len(request.TransferEncoding) > 0 && strings.EqualFold(request.TransferEncoding[len(request.TransferEncoding)-1], "chunked")
	if chunked {
		request.ContentLength = -1
		request.Body = &chunkedBody{source: body, chunks: httputil.NewChunkedReader(body)}
	} else {
		request.Body = &drainBody{source: body, remaining: max(request.ContentLength, 0)}
	}
	return request, reasons, nil
}

// lenientRequestHead never fails on a complete header block. Its fields are
// an analysis view; the saved evidence remains the original bytes.
func lenientRequestHead(head []byte) (*http.Request, []string) {
	reasons := []string{ReasonLenientRequest}
	lines := strings.Split(string(head), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	request := &http.Request{Header: http.Header{}, ProtoMajor: 1, ProtoMinor: 1, Proto: "HTTP/1.1"}
	line := lines[0]
	method, rest, found := strings.Cut(line, " ")
	request.Method = method
	target := rest
	if index := strings.LastIndexByte(rest, ' '); found && index >= 0 && strings.HasPrefix(rest[index+1:], "HTTP/") {
		target = rest[:index]
		proto := rest[index+1:]
		if major, minor, ok := http.ParseHTTPVersion(proto); ok {
			request.Proto, request.ProtoMajor, request.ProtoMinor = proto, major, minor
		} else {
			reasons = append(reasons, ReasonMalformedRequestLine)
		}
	} else {
		reasons = append(reasons, ReasonMalformedRequestLine)
	}
	request.RequestURI = target
	if parsed, err := url.ParseRequestURI(target); err == nil {
		request.URL = parsed
	} else {
		request.URL = &url.URL{Opaque: target}
	}
	var last string
	malformed := false
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && last != "" {
			values := request.Header[last]
			values[len(values)-1] += " " + strings.TrimSpace(line)
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !validHeaderName(name) {
			malformed = true
		}
		if name = strings.TrimSpace(name); !ok || name == "" {
			continue
		}
		last = textproto.CanonicalMIMEHeaderKey(name)
		request.Header[last] = append(request.Header[last], strings.TrimSpace(value))
	}
	if malformed {
		reasons = append(reasons, ReasonMalformedHeaderLine)
	}
	request.Host = request.Header.Get("Host")
	if request.Host == "" && request.URL != nil {
		request.Host = request.URL.Host
	}
	request.Header.Del("Host")
	var codings []string
	for _, value := range request.Header.Values("Transfer-Encoding") {
		for _, coding := range strings.Split(value, ",") {
			if coding = strings.TrimSpace(coding); coding != "" {
				codings = append(codings, strings.ToLower(coding))
			}
		}
	}
	lengths := request.Header.Values("Content-Length")
	if len(codings) > 0 && codings[len(codings)-1] == "chunked" {
		request.TransferEncoding = codings
		if len(lengths) > 0 {
			reasons = append(reasons, ReasonConflictingFraming)
		}
		return request, reasons
	}
	if len(lengths) == 0 {
		return request, reasons
	}
	// With conflicting values the first is used: the analysis cannot know
	// which one the server honoured, so the request is marked ambiguous.
	for _, value := range lengths[1:] {
		if strings.TrimSpace(value) != strings.TrimSpace(lengths[0]) {
			reasons = append(reasons, ReasonAmbiguousLength)
			break
		}
	}
	length, err := strconv.ParseInt(strings.TrimSpace(lengths[0]), 10, 64)
	if err != nil || length < 0 {
		reasons = append(reasons, ReasonInvalidLength)
		length = 0
	}
	request.ContentLength = length
	return request, reasons
}

// drainBody reads exactly remaining bytes and consumes what is left on
// Close, as net/http request bodies do, so a following pipelined message is
// read from its first byte. A source that ends early is io.ErrUnexpectedEOF,
// which framing callers use to wait for the rest of the message.
type drainBody struct {
	source    io.Reader
	remaining int64
	closed    bool
}

func (b *drainBody) Read(p []byte) (int, error) {
	if b.closed {
		return 0, http.ErrBodyReadAfterClose
	}
	if b.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.source.Read(p)
	b.remaining -= int64(n)
	if errors.Is(err, io.EOF) {
		if b.remaining > 0 {
			return n, io.ErrUnexpectedEOF
		}
		err = nil
	}
	if err == nil && b.remaining == 0 {
		err = io.EOF
	}
	return n, err
}

func (b *drainBody) Close() error {
	if b.closed {
		return nil
	}
	_, err := io.Copy(io.Discard, b)
	b.closed = true
	return err
}

// chunkedBody decodes chunks and then consumes the trailer section.
type chunkedBody struct {
	source  *bufio.Reader
	chunks  io.Reader
	done    bool
	closed  bool
	trailer error
}

func (b *chunkedBody) Read(p []byte) (int, error) {
	if b.closed {
		return 0, http.ErrBodyReadAfterClose
	}
	if b.done {
		return 0, b.trailerResult()
	}
	n, err := b.chunks.Read(p)
	if errors.Is(err, io.EOF) {
		b.done = true
		b.trailer = consumeTrailer(b.source)
		return n, b.trailerResult()
	}
	return n, err
}

func (b *chunkedBody) trailerResult() error {
	if b.trailer != nil {
		return b.trailer
	}
	return io.EOF
}

func (b *chunkedBody) Close() error {
	if b.closed {
		return nil
	}
	_, err := io.Copy(io.Discard, b)
	b.closed = true
	return err
}

func consumeTrailer(source *bufio.Reader) error {
	for size := 0; ; {
		line, err := source.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if len(line) <= 2 && strings.TrimRight(string(line), "\r\n") == "" {
			return nil
		}
		if size += len(line); size > 32<<10 {
			return errors.New("chunked trailer too large")
		}
	}
}

// IsParseNote reports reasons that describe how a request was read rather
// than missing bytes.
func IsParseNote(reason string) bool {
	switch reason {
	case ReasonLenientRequest, ReasonMalformedRequestLine, ReasonMalformedHeaderLine, ReasonAmbiguousLength, ReasonInvalidLength, ReasonConflictingFraming:
		return true
	}
	return false
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte("\"(),/:;<=>?@[\\]{}", c) >= 0 {
			return false
		}
	}
	return true
}
