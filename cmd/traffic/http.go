package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

type HTTPProcessor struct {
	s              *Store
	mu             sync.Mutex
	pending        map[string][]Transaction
	responses      map[string][]responseData
	responseBytes  int64
	requestMethods map[string][]string
	requestReady   chan struct{}
	responseCount  int
	wg             sync.WaitGroup
	slots          chan struct{}
}

type responseData struct {
	raw        []byte
	status     int
	truncated  bool
	incomplete bool
}

func newHTTP(s *Store) *HTTPProcessor {
	return &HTTPProcessor{s: s, requestMethods: map[string][]string{}, requestReady: make(chan struct{}), pending: map[string][]Transaction{}, responses: map[string][]responseData{}, slots: make(chan struct{}, 2000)}
}
func (p *HTTPProcessor) process(r io.Reader, key, client, source string, pid int, incomplete bool) {
	br := bufio.NewReaderSize(r, 32768)
	for {
		prefix, e := br.Peek(5)
		if e != nil {
			return
		}
		if prefix[0] >= 20 && prefix[0] <= 23 && prefix[1] == 3 && prefix[2] <= 3 {
			p.observeTLSRecords(br)
			return
		}
		if prefix[0] < 65 || prefix[0] > 90 {
			return
		}
		if !boundedHeader(br) {
			return
		}
		if strings.HasPrefix(string(prefix), "HTTP/") {
			request := p.responseRequest(key)
			resp, e := http.ReadResponse(br, request)
			if e != nil {
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
			truncated := len(body) > responseLimit
			if truncated {
				body = body[:responseLimit]
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
			raw, dumpErr := httputil.DumpResponse(resp, true)
			if dumpErr != nil || truncated {
				headers, _ := httputil.DumpResponse(resp, false)
				raw = append(headers, body...)
			}
			p.mu.Lock()
			queue := p.pending[key]
			if len(queue) > 0 {
				t := queue[0]
				if err := p.s.restore(&t); err != nil {
					t.Incomplete = true
					p.s.problem(err)
				}
				if len(queue) == 1 {
					delete(p.pending, key)
				} else {
					p.pending[key] = queue[1:]
				}
				t.Response = raw
				t.Status = resp.StatusCode
				t.Truncated = t.Truncated || truncated
				if state, ok := r.(interface{ Incomplete() bool }); ok {
					incomplete = incomplete || state.Incomplete()
				}
				t.Incomplete = t.Incomplete || e != nil || incomplete
				if err := p.s.save(t); err != nil {
					p.s.fail(err)
				}
			}
			if len(queue) == 0 {
				rs := p.responses[key]
				if len(rs) < 100 && p.responseCount < 2000 && p.responseBytes+int64(len(raw)) <= 8<<20 {
					p.responseBytes += int64(len(raw))
					p.responseCount++
					p.responses[key] = append(rs, responseData{raw, resp.StatusCode, truncated, e != nil || incomplete})
				} else {
					p.s.mu.Lock()
					p.s.stats.QueueDropped++
					p.s.mu.Unlock()
				}
			}
			p.mu.Unlock()
		} else {
			req, e := http.ReadRequest(br)
			if e != nil {
				return
			}
			if req.ProtoMajor != 1 {
				p.s.problem(fmt.Errorf("unsupported HTTP protocol %s", req.Proto))
				return
			}
			// Publish the method before reading the request body. Responses can
			// run on another packet stream, and HEAD framing needs this method.
			p.mu.Lock()
			if len(p.requestMethods) >= 2000 {
				p.requestMethods = map[string][]string{}
			}
			methods := p.requestMethods[key]
			if len(methods) >= 100 {
				methods = methods[1:]
			}
			if len(p.responses[key]) == 0 {
				p.requestMethods[key] = append(methods, req.Method)
				close(p.requestReady)
				p.requestReady = make(chan struct{})
			}
			p.mu.Unlock()
			body, e := io.ReadAll(io.LimitReader(req.Body, int64(requestLimit)+1))
			if closeErr := req.Body.Close(); e == nil {
				e = closeErr
			}
			truncated := len(body) > requestLimit
			if truncated {
				body = body[:requestLimit]
			}
			req.Body = io.NopCloser(bytes.NewReader(body))
			raw, dumpErr := httputil.DumpRequest(req, true)
			if dumpErr != nil || truncated {
				headers, _ := httputil.DumpRequest(req, false)
				raw = append(headers, body...)
			}
			if state, ok := r.(interface{ Incomplete() bool }); ok {
				incomplete = incomplete || state.Incomplete()
			}
			captured := time.Now().UTC()
			if timed, ok := r.(interface{ CaptureTime() time.Time }); ok {
				if stamp := timed.CaptureTime(); !stamp.IsZero() {
					captured = stamp
				}
			}
			t := Transaction{ID: fmt.Sprintf("%x-%x", time.Now().UnixNano(), serial.Add(1)), Time: captured, Source: source, Host: req.Host, Client: client, Connection: key, Method: req.Method, URL: req.RequestURI, Request: raw, Incomplete: incomplete || e != nil, Truncated: truncated, PID: pid}
			if endpoint, ok := r.(interface{ LocalEndpoint() string }); ok {
				t.LocalEndpoint = endpoint.LocalEndpoint()
			}
			p.mu.Lock()
			for k, items := range p.pending {
				if len(items) > 0 && captured.Sub(items[len(items)-1].Time) > time.Minute {
					delete(p.pending, k)
					delete(p.requestMethods, k)
					for _, orphan := range p.responses[k] {
						p.responseBytes -= int64(len(orphan.raw))
						p.responseCount--
					}
					delete(p.responses, k)
				}
			}
			if len(p.pending) > 2000 {
				p.pending = map[string][]Transaction{}
			}
			q := p.pending[key]
			if len(q) >= 100 {
				q = q[1:]
			}
			if rs := p.responses[key]; len(rs) > 0 {
				rd := rs[0]
				p.responseBytes -= int64(len(rd.raw))
				p.responseCount--
				if len(rs) == 1 {
					delete(p.responses, key)
				} else {
					p.responses[key] = rs[1:]
				}
				t.Response = rd.raw
				t.Status = rd.status
				t.Truncated = t.Truncated || rd.truncated
				t.Incomplete = t.Incomplete || rd.incomplete
			}
			if len(t.Response) == 0 {
				p.pending[key] = append(q, Transaction{ID: t.ID, Time: t.Time, Method: t.Method, Source: t.Source, Client: t.Client, Connection: t.Connection, PID: t.PID, Host: t.Host})
			}
			if err := p.s.save(t); err != nil {
				p.s.fail(err)
			}
			p.mu.Unlock()
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
		p.mu.Unlock()
		if len(methods) > 0 {
			return &http.Request{Method: methods[0]}
		}
		select {
		case <-ready:
		case <-deadline.C:
			return nil
		}
	}
}
