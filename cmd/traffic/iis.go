package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

type iisEvent struct {
	Protocol   string      `json:"protocol"`
	Type       string      `json:"type"`
	ID         string      `json:"id"`
	Connection string      `json:"connection"`
	Time       time.Time   `json:"time"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Headers    [][2]string `json:"headers"`
	Client     string      `json:"client"`
	Local      string      `json:"local"`
	Status     int         `json:"status"`
	Data       []byte      `json:"data_b64"`
	Count      uint64      `json:"count"`
	Length     int64       `json:"length"`
	Reason     string      `json:"reason"`
}

type iisRequest struct {
	transaction     Transaction
	requestHeaders  http.Header
	responseHeaders http.Header
	requestBody     []byte
	responseBody    []byte
	requestObserved int64
	requestComplete bool
	gap             bool
}

type iisAssembler struct {
	store   *Store
	target  session.Target
	pending map[string]*iisRequest
	bytes   int
}

func iisHeaders(fields [][2]string) http.Header {
	headers := make(http.Header)
	for _, field := range fields {
		headers.Add(field[0], field[1])
	}
	return headers
}

// HTTP.sys returns parsed headers and dechunked entity bytes. Keep original API
// events separately, and serialize a consistent HTTP/1.1 representation here.
func iisMessage(firstLine string, headers http.Header, body []byte) []byte {
	headers = headers.Clone()
	headers.Del("Transfer-Encoding")
	headers.Del("Trailer")
	headers.Set("Content-Length", strconv.Itoa(len(body)))
	var output bytes.Buffer
	output.WriteString(firstLine + "\r\n")
	headers.Write(&output)
	output.WriteString("\r\n")
	output.Write(body)
	return output.Bytes()
}

func (a *iisAssembler) save(request *iisRequest, responseComplete bool) error {
	t := &request.transaction
	t.Request = iisMessage(t.Method+" "+t.URL+" HTTP/1.1", request.requestHeaders, request.requestBody)
	if t.Status > 0 {
		body := request.responseBody
		if strings.Contains(strings.ToLower(request.responseHeaders.Get("Transfer-Encoding")), "chunked") {
			var err error
			body, err = io.ReadAll(io.LimitReader(httputil.NewChunkedReader(bytes.NewReader(body)), int64(responseLimit)+1))
			if len(body) > responseLimit {
				body = body[:responseLimit]
				t.Truncated = true
			}
			if err != nil && responseComplete && !request.gap {
				request.gap = true
				a.store.mu.Lock()
				a.store.stats.TLSDropped++
				a.store.mu.Unlock()
				a.store.problem(fmt.Errorf("IIS chunked response: %w", err))
			}
		}
		t.Response = iisMessage(fmt.Sprintf("HTTP/1.1 %d %s", t.Status, http.StatusText(t.Status)), request.responseHeaders, body)
	}
	complete := request.requestComplete
	if length := request.requestHeaders.Get("Content-Length"); length != "" {
		expected, err := strconv.ParseInt(length, 10, 64)
		complete = complete || (err == nil && expected == request.requestObserved)
	}
	t.Incomplete = request.gap || !complete || !responseComplete || t.Status == 0
	return a.store.save(*t)
}

func (a *iisAssembler) ingest(event iisEvent) error {
	if a.pending == nil {
		a.pending = make(map[string]*iisRequest)
	}
	if event.Type == "loss" {
		a.store.mu.Lock()
		a.store.stats.TLSDropped += event.Count
		a.store.mu.Unlock()
		for _, request := range a.pending {
			request.gap = true
		}
		return nil
	}
	if event.Type == "request" {
		if _, exists := a.pending[event.ID]; exists {
			return fmt.Errorf("duplicate active IIS request %s", event.ID)
		}
		if len(a.pending) >= 128 || a.bytes >= 32<<20 {
			for id, request := range a.pending {
				request.gap = true
				if err := a.save(request, false); err != nil {
					return err
				}
				a.bytes -= len(request.requestBody) + len(request.responseBody)
				delete(a.pending, id)
				break
			}
			a.store.mu.Lock()
			a.store.stats.TLSDropped++
			a.store.mu.Unlock()
		}
		headers := iisHeaders(event.Headers)
		request := &iisRequest{requestHeaders: headers, transaction: Transaction{
			ID: fmt.Sprintf("%x-%x", time.Now().UnixNano(), serial.Add(1)), Time: event.Time,
			PID: a.target.PID, TargetID: a.target.ID, Service: "iis", Backend: "iis-httpapi",
			Connection: "tls:iis:" + a.target.ID + ":" + event.Connection + ":" + event.ID,
			Source:     "tls:iis-httpapi", Client: event.Client, LocalEndpoint: event.Local,
			Method: event.Method, URL: event.URL, Host: headers.Get("Host"),
		}}
		a.pending[event.ID] = request
		return a.save(request, false)
	}
	request := a.pending[event.ID]
	if request == nil {
		return nil
	}
	switch event.Type {
	case "request-body", "response-body":
		body, limit := &request.requestBody, requestLimit
		if event.Type == "response-body" {
			body, limit = &request.responseBody, responseLimit
			if strings.Contains(strings.ToLower(request.responseHeaders.Get("Transfer-Encoding")), "chunked") {
				limit = responseLimit*8 + 32768
			}
		} else {
			request.requestObserved += event.Length
		}
		remaining := min(limit-len(*body), (32<<20)-a.bytes)
		data := event.Data
		if len(data) > remaining {
			data = data[:max(remaining, 0)]
			request.transaction.Truncated = true
			if a.bytes+len(event.Data) > 32<<20 {
				request.gap = true
				a.store.mu.Lock()
				a.store.stats.TLSDropped++
				a.store.mu.Unlock()
			}
		}
		*body = append(*body, data...)
		a.bytes += len(data)
	case "request-end":
		request.requestComplete = true
	case "response":
		request.transaction.Status = event.Status
		request.responseHeaders = iisHeaders(event.Headers)
		return a.save(request, false)
	case "truncated":
		request.transaction.Truncated = true
	case "gap":
		request.gap = true
		a.store.mu.Lock()
		a.store.stats.TLSDropped++
		a.store.mu.Unlock()
		a.store.problem(fmt.Errorf("IIS request %s: %s", event.ID, event.Reason))
	case "response-end":
		if err := a.save(request, true); err != nil {
			return err
		}
		a.bytes -= len(request.requestBody) + len(request.responseBody)
		delete(a.pending, event.ID)
	}
	return nil
}

func (a *iisAssembler) finish() error {
	for _, request := range a.pending {
		if err := a.save(request, false); err != nil {
			return err
		}
	}
	a.pending = nil
	a.bytes = 0
	return nil
}
