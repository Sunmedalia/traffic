package replay

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

type HTTPProcessor struct {
	h2mu           sync.Mutex
	h2             map[string]*h2Connection
	h2bytes        int
	s              *Store
	mu             sync.Mutex
	pending        map[string][]Transaction
	responses      map[string][]responseData
	responseBytes  int64
	requestMethods map[string][]string
	requestReady   chan struct{}
	responseCount  int
	pairingLost    map[string]string
	pairingStopped bool
	wg             sync.WaitGroup
	slots          chan struct{}
}

type responseData struct {
	raw        []byte
	observed   time.Time
	status     int
	truncated  bool
	incomplete bool
}

// packetParserLimit bounds concurrently parsed TCP directions.
var packetParserLimit = 2000

const (
	http1ConnectionLimit = 2000
	http1PipelineLimit   = 100
)

func newHTTP(s *Store) *HTTPProcessor {
	return &HTTPProcessor{s: s, requestMethods: map[string][]string{}, requestReady: make(chan struct{}), pending: map[string][]Transaction{}, responses: map[string][]responseData{}, slots: make(chan struct{}, packetParserLimit)}
}
func (p *HTTPProcessor) process(r io.Reader, key, client, source string, pid int, incomplete bool) {
	packetStream, _ := r.(*queuedStream)
	bufferSize := 32768
	if frame, ok := r.(interface{ FramingComplete() bool }); ok && frame.FramingComplete() {
		if sized, ok := r.(interface{ Len() int }); ok && sized.Len() > 0 {
			// A complete TLS message already has all its bytes in memory. A
			// fresh 32 KiB buffer for every small request/response creates avoidable
			// allocation pressure; large messages retain the existing header limit.
			bufferSize = min(bufferSize, sized.Len())
		}
	}
	recorder := &rawRecorder{source: r}
	br, releaseReader := borrowHTTPReader(recorder, bufferSize)
	defer releaseReader()
	for {
		if state, ok := r.(interface{ Aborted() bool }); ok && state.Aborted() {
			return
		}
		prefix, e := br.Peek(5)
		if e != nil {
			if len(prefix) > 0 {
				p.s.gap("http1", key, "partial_message_start", "fragments", 1)
			}
			return
		}
		if string(prefix) == "PRI *" || (prefix[0] == 0 && prefix[3] == 4) {
			p.processHTTP2Reader(br, key, client, source, pid, string(prefix) == "PRI *", r)
			return
		}
		if prefix[0] >= 20 && prefix[0] <= 23 && prefix[1] == 3 && prefix[2] <= 3 {
			p.observeTLSRecords(br)
			return
		}
		if prefix[0] < 65 || prefix[0] > 90 {
			p.s.gap("protocol", key, "unsupported_or_midstream", "directions", 1)
			return
		}
		if !boundedHeader(br) {
			p.s.gap("http1", key, "header_limit_or_partial", "directions", 1)
			p.invalidate(key, "header_limit_or_partial")
			return
		}
		if strings.HasPrefix(string(prefix), "HTTP/") {
			p.mu.Lock()
			blocked := p.http1PairingLossLocked(key) != ""
			p.mu.Unlock()
			if blocked {
				return
			}
			var request *http.Request
			if _, serial := r.(interface{ FramingComplete() bool }); serial {
				// TLS frames are consumed by one event loop. Waiting here for a
				// request in the same queue prevents that request from arriving.
				request = p.responseRequestNow(key)
			} else {
				request = p.responseRequest(key)
			}
			headerLength := bufferedHeaderLength(br)
			recorder.begin(br, headerLength+responseLimit+rawFramingSlack)
			resp, e := http.ReadResponse(br, request)
			if e != nil {
				p.s.gap("http1", key, "response_parse_failure", "directions", 1)
				p.invalidate(key, "response_parse_failure")
				return
			}
			if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != 101 {
				continue
			}
			p.mu.Lock()
			if methods := p.requestMethods[key]; len(methods) > 1 {
				p.requestMethods[key] = methods[1:]
			} else {
				delete(p.requestMethods, key)
			}
			p.mu.Unlock()
			body, e := io.ReadAll(io.LimitReader(resp.Body, int64(responseLimit)+1))
			if closeErr := resp.Body.Close(); e == nil {
				e = closeErr
			}
			var observed time.Time
			if packetStream != nil {
				observed = packetStream.latest
			}
			if state, ok := r.(interface{ FramingComplete() bool }); ok && state.FramingComplete() && len(body) > responseLimit {
				e = nil
			}
			truncated := len(body) > responseLimit
			raw := savedMessage(recorder, br, headerLength, responseLimit, len(resp.TransferEncoding) > 0, &truncated)
			p.mu.Lock()
			if p.http1PairingLossLocked(key) != "" {
				p.mu.Unlock()
				return
			}
			if state, ok := r.(interface{ Aborted() bool }); ok && state.Aborted() {
				p.mu.Unlock()
				return
			}
			queue := p.pending[key]
			if state, ok := r.(interface{ Incomplete() bool }); ok {
				incomplete = incomplete || state.Incomplete()
			}
			if len(queue) > 0 {
				// Popping the FIFO entry makes this goroutine the only owner of
				// the request, so restoring and saving it need not hold p.mu.
				t := queue[0]
				if len(queue) == 1 {
					delete(p.pending, key)
				} else {
					p.pending[key] = queue[1:]
				}
				parked, inMemory := p.s.requests.take(t.ID)
				p.mu.Unlock()
				if inMemory {
					t = parked
				} else if err := p.s.restore(&t); err != nil {
					// The cache spilled this request; SQLite must hold it.
					t.Incomplete = true
					p.s.problem(err)
				}
				t.Response = raw
				t.ResponseTime = observed
				t.Status = resp.StatusCode
				t.Truncated = t.Truncated || truncated
				t.Incomplete = t.Incomplete || e != nil || incomplete
				if err := p.s.save(t); err != nil {
					p.s.fail(err)
				}
				continue
			}
			rs := p.responses[key]
			if len(rs) < http1PipelineLimit && p.responseCount < http1ConnectionLimit && p.responseBytes+int64(len(raw)) <= 8<<20 {
				p.responseBytes += int64(len(raw))
				p.responseCount++
				p.responses[key] = append(rs, responseData{raw: raw, observed: observed, status: resp.StatusCode, truncated: truncated, incomplete: e != nil || incomplete})
			} else {
				p.loseHTTP1PairingLocked(key, "response_queue_limit")
				p.s.mu.Lock()
				p.s.stats.QueueDropped++
				p.s.mu.Unlock()
			}
			p.mu.Unlock()
		} else {
			captured := time.Now().UTC()
			if timed, ok := r.(interface{ CaptureTime() time.Time }); ok {
				if stamp := timed.CaptureTime(); !stamp.IsZero() {
					captured = stamp
				}
			}
			headerLength := bufferedHeaderLength(br)
			recorder.begin(br, headerLength+requestLimit+rawFramingSlack)
			req, parseReasons, e := session.ReadRequest(br)
			if e != nil {
				p.s.gap("http1", key, "request_parse_failure", "directions", 1)
				p.invalidate(key, "request_parse_failure")
				return
			}
			if req.ProtoMajor != 1 {
				p.s.problem(fmt.Errorf("unsupported HTTP protocol %s", req.Proto))
				return
			}
			// Publish the method before reading the request body. Responses can
			// run on another packet stream, and HEAD framing needs this method.
			p.mu.Lock()
			methods := p.requestMethods[key]
			if len(p.responses[key]) == 0 && p.http1PairingLossLocked(key) == "" {
				switch {
				case len(methods) >= http1PipelineLimit:
					p.loseHTTP1PairingLocked(key, "pipeline_limit")
				case len(methods) == 0 && len(p.requestMethods) >= http1ConnectionLimit:
					p.loseHTTP1PairingLocked(key, "method_queue_limit")
				default:
					p.requestMethods[key] = append(methods, req.Method)
					p.signalRequestLocked()
				}
			}
			p.mu.Unlock()
			body, e := io.ReadAll(io.LimitReader(req.Body, int64(requestLimit)+1))
			if closeErr := req.Body.Close(); e == nil {
				e = closeErr
			}
			if state, ok := r.(interface{ FramingComplete() bool }); ok && state.FramingComplete() && len(body) > requestLimit {
				e = nil
			}
			truncated := len(body) > requestLimit
			raw := savedMessage(recorder, br, headerLength, requestLimit, req.ContentLength < 0, &truncated)
			if state, ok := r.(interface{ Incomplete() bool }); ok {
				incomplete = incomplete || state.Incomplete()
			}
			t := Transaction{ID: fmt.Sprintf("%x-%x", time.Now().UnixNano(), serial.Add(1)), Time: captured, Source: source, Host: req.Host, Client: client, Connection: key, Method: req.Method, URL: req.RequestURI, Request: raw, Incomplete: incomplete || e != nil, Truncated: truncated, PID: pid, IntegrityReasons: parseReasons}
			if origin, ok := r.(interface {
				CaptureBackend() string
				CaptureService() string
			}); ok {
				t.Backend, t.Service = origin.CaptureBackend(), origin.CaptureService()
			}
			if identity, ok := r.(interface{ TargetIdentity() string }); ok {
				t.TargetID = identity.TargetIdentity()
			}
			if endpoint, ok := r.(interface{ LocalEndpoint() string }); ok {
				t.LocalEndpoint = endpoint.LocalEndpoint()
			}
			// Normalize the copy a parked request keeps before taking p.mu, as
			// a write at this point would have. Exactly one of t and parked is
			// used; clipping keeps prepare's appends out of t's reasons.
			parked := t
			parked.IntegrityReasons = slices.Clip(parked.IntegrityReasons)
			p.s.prepare(&parked)
			p.mu.Lock()
			if state, ok := r.(interface{ Aborted() bool }); ok && state.Aborted() {
				p.mu.Unlock()
				t.Incomplete = true
				t.IntegrityReasons = append(t.IntegrityReasons, "tcp_stream_gap")
				if err := p.s.save(t); err != nil {
					p.s.fail(err)
				}
				return
			}
			q, rs := p.pending[key], p.responses[key]
			if p.http1PairingLossLocked(key) == "" {
				switch {
				case len(q) >= http1PipelineLimit:
					p.loseHTTP1PairingLocked(key, "pipeline_limit")
				case len(q) == 0 && len(rs) == 0 && len(p.pending) >= http1ConnectionLimit:
					p.loseHTTP1PairingLocked(key, "pending_connection_limit")
				}
			}
			if reason := p.http1PairingLossLocked(key); reason != "" {
				t.Incomplete = true
				t.IntegrityReasons = append(t.IntegrityReasons, reason)
			} else if len(rs) > 0 {
				rd := rs[0]
				p.responseBytes -= int64(len(rd.raw))
				p.responseCount--
				if len(rs) == 1 {
					delete(p.responses, key)
				} else {
					p.responses[key] = rs[1:]
				}
				t.Response = rd.raw
				t.ResponseTime = rd.observed
				t.Status = rd.status
				t.Truncated = t.Truncated || rd.truncated
				t.Incomplete = t.Incomplete || rd.incomplete
			} else {
				// Park the request before p.mu is released: a response that
				// pops this FIFO entry must find it parked or already spilled.
				p.pending[key] = append(q, Transaction{ID: t.ID, Time: t.Time, Method: t.Method, Source: t.Source, Client: t.Client, Connection: t.Connection, PID: t.PID, Host: t.Host})
				if err := p.s.parkPending(parked); err != nil {
					p.s.fail(err)
				}
				p.mu.Unlock()
				continue
			}
			p.mu.Unlock()
			if err := p.s.save(t); err != nil {
				p.s.fail(err)
			}
		}
	}
}

// Count complete outer records after TCP reassembly so retransmissions and
// segmentation within an interface do not inflate the diagnostic counter.
func (p *HTTPProcessor) observeTLSRecords(reader io.Reader) {
	var header [5]byte
	for {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return
		}
		length := int64(header[3])<<8 | int64(header[4])
		if header[0] < 20 || header[0] > 23 || header[1] != 3 || header[2] > 3 || length > (1<<14)+2048 {
			return
		}
		if _, err := io.CopyN(io.Discard, reader, length); err != nil {
			return
		}
		p.s.mu.Lock()
		p.s.stats.TLSWireRecords++
		p.s.mu.Unlock()
	}
}

// rawFramingSlack leaves room for chunk-size lines and trailers on top of the
// header and decoded body limits when keeping a message's original bytes.
const rawFramingSlack = 64 << 10

func bufferedHeaderLength(br *bufio.Reader) int {
	buffered, _ := br.Peek(br.Buffered())
	return max(session.HeaderBlockLength(buffered), 0)
}

// savedMessage returns the original bytes of the message just parsed. A
// Content-Length body over the limit is cut at the same decoded-body limit as
// before; chunked framing keeps up to rawFramingSlack extra encoded bytes.
func savedMessage(recorder *rawRecorder, br *bufio.Reader, headerLength, limit int, chunked bool, truncated *bool) []byte {
	raw, cut := recorder.end(br)
	if *truncated && !chunked && len(raw) > headerLength+limit {
		raw = raw[:headerLength+limit]
	}
	*truncated = *truncated || cut
	return raw
}

// Inspect a bounded header without consuming or waiting for bytes beyond its terminator.
func boundedHeader(br *bufio.Reader) bool {
	for {
		b, _ := br.Peek(br.Buffered())
		if bytes.Contains(b, []byte("\r\n\r\n")) || bytes.Contains(b, []byte("\n\n")) {
			return true
		}
		if br.Buffered() >= br.Size() {
			return false
		}
		if _, e := br.Peek(br.Buffered() + 1); e != nil {
			return false
		}
	}
}

// Packet directions are parsed concurrently. Allow the request header to arrive
// before choosing response body framing, while bounding waits for orphan data.
func (p *HTTPProcessor) responseRequest(key string) *http.Request {
	deadline := time.NewTimer(100 * time.Millisecond)
	defer deadline.Stop()
	for {
		p.mu.Lock()
		methods := p.requestMethods[key]
		ready := p.requestReady
		if p.http1PairingLossLocked(key) != "" {
			p.mu.Unlock()
			return nil
		}
		if len(methods) > 0 {
			method := methods[0]
			p.mu.Unlock()
			return &http.Request{Method: method}
		}
		p.mu.Unlock()
		select {
		case <-ready:
		case <-deadline.C:
			return nil
		}
	}
}

func (p *HTTPProcessor) responseRequestNow(key string) *http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	if methods := p.requestMethods[key]; len(methods) > 0 {
		return &http.Request{Method: methods[0]}
	}
	return nil
}
