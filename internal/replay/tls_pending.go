package replay

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type frameContext struct {
	backend    string
	service    string
	targetID   string
	incomplete bool
	local      string
	connection string
	client     string
	pid        int
	first      time.Time
	updated    time.Time
}

type capturedReader struct {
	*bytes.Reader
	captured time.Time
	local    string
	complete bool
	targetID string
	backend  string
	service  string
}

func (r capturedReader) FramingComplete() bool { return r.complete }

func (r capturedReader) CaptureTime() time.Time { return r.captured }

// ingest serializes frame bookkeeping with the idle-expiry worker. HTTP parsing
// and storage happen outside the frame mutex.
func (f *Frames) ingest(key string, payload []byte, meta frameContext, head bool, p *HTTPProcessor) {
	now := meta.updated
	if now.IsZero() {
		now = time.Now().UTC()
	}
	f.mu.Lock()
	if f.contexts == nil {
		f.contexts = make(map[string]frameContext)
	}
	if previous, ok := f.contexts[key]; ok {
		meta.first = previous.first
		meta.incomplete = meta.incomplete || previous.incomplete
	} else {
		if meta.first.IsZero() {
			meta.first = now
		}
	}
	meta.updated = now
	heads := []bool{head}
	p.mu.Lock()
	if queue := p.pending["tls:"+meta.connection]; len(queue) > 0 {
		heads = nil
		for _, record := range queue {
			heads = append(heads, record.Method == "HEAD")
		}
	}
	p.mu.Unlock()
	chunks, gap := f.feed(key, payload, heads...)
	for _, item := range f.evicted {
		if item.key == key || (item.meta.connection != "" && item.meta.connection == meta.connection) {
			gap = true
		}
	}
	frameGap := gap
	gap = gap || meta.incomplete
	if len(f.buffers[key]) > 0 || f.http2[key] {
		f.contexts[key] = meta
	} else {
		delete(f.contexts, key)
	}
	for existing := range f.contexts {
		if len(f.buffers[existing]) == 0 && !f.http2[existing] {
			delete(f.contexts, existing)
		}
	}
	isHTTP2 := f.http2[key]
	evicted := f.evicted
	f.evicted = nil
	f.mu.Unlock()
	for _, item := range evicted {
		connection := item.meta.connection
		if connection == "" {
			connection = meta.connection
		}
		p.s.gap("tls", connection, "buffer_evicted", "connections", 1)
		p.invalidate("tls:"+connection, "buffer_evicted")
		if len(item.data) > 0 {
			record := Transaction{Time: item.meta.first, Source: "tls-hook-fragment", Client: item.meta.client, Connection: "tls:" + connection, PID: item.meta.pid, TargetID: item.meta.targetID, Backend: item.meta.backend, Service: item.meta.service, LocalEndpoint: item.meta.local, Request: item.data, Incomplete: true, IntegrityReasons: []string{"buffer_evicted"}}
			if err := p.s.save(record); err != nil {
				p.s.fail(err)
			}
		}
	}
	if frameGap {
		p.s.mu.Lock()
		p.s.stats.TLSDropped++
		p.s.mu.Unlock()
		p.s.gap("tls", meta.connection, "frame_gap", "events", 1)
		if frameGap {
			p.invalidate("tls:"+meta.connection, "frame_gap")
		}
	}
	for _, chunk := range chunks {
		if isHTTP2 {
			_, portText, _ := net.SplitHostPort(meta.local)
			port, _ := strconv.Atoi(portText)
			request := strings.HasSuffix(key, "read")
			if !capturePorts[port] {
				request = !request
			}
			h2meta := meta
			h2meta.first = now
			p.ingestHTTP2("tls:"+meta.connection, request, chunk, h2meta, "tls-hook")
			continue
		}
		p.process(capturedReader{bytes.NewReader(chunk), meta.first, meta.local, true, meta.targetID, meta.backend, meta.service}, "tls:"+meta.connection, meta.client, "tls-hook", meta.pid, gap)
	}
}

func (f *Frames) expire(now time.Time, all bool, p *HTTPProcessor, connection string) {
	type partial struct {
		data []byte
		meta frameContext
	}
	var expired []partial
	f.mu.Lock()
	for key, meta := range f.contexts {
		// HTTP/2 keeps its framing and HPACK state across idle periods;
		// connection count and buffered bytes are bounded separately.
		if !all && f.http2[key] {
			continue
		}
		if (connection == "" || meta.connection == connection) && (all || now.Sub(meta.updated) >= time.Minute) {
			expired = append(expired, partial{f.buffers[key], meta})
			f.remove(key)
			delete(f.http2, key)
		}
	}
	f.mu.Unlock()
	for _, item := range expired {
		if len(item.data) == 0 {
			p.closeHTTP2("tls:"+item.meta.connection, "http2_connection_closed")
			continue
		}
		if !bytes.Contains(item.data, []byte("\r\n\r\n")) && !bytes.Contains(item.data, []byte("\n\n")) {
			record := Transaction{LocalEndpoint: item.meta.local, Time: item.meta.first, Source: "tls-hook-fragment", Client: item.meta.client, Connection: "tls:" + item.meta.connection, PID: item.meta.pid, TargetID: item.meta.targetID, Backend: item.meta.backend, Service: item.meta.service, Request: item.data, Incomplete: true}
			if err := p.s.save(record); err != nil {
				p.s.fail(err)
			}
			p.invalidate("tls:"+item.meta.connection, "partial_frame_closed")
			continue
		}
		p.process(capturedReader{bytes.NewReader(item.data), item.meta.first, item.meta.local, false, item.meta.targetID, item.meta.backend, item.meta.service}, "tls:"+item.meta.connection, item.meta.client, "tls-hook", item.meta.pid, true)
		p.s.gap("tls", item.meta.connection, "partial_frame_closed", "fragments", 1)
		p.invalidate("tls:"+item.meta.connection, "partial_frame_closed")
	}
}

func (f *Frames) startExpiry(ctx context.Context, p *HTTPProcessor) func() {
	lifetime, cancel := context.WithCancel(ctx)
	var worker sync.WaitGroup
	worker.Add(1)
	go func() {
		defer worker.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case now := <-ticker.C:
				f.expire(now, false, p, "")
			}
		}
	}()
	return func() { cancel(); worker.Wait(); f.expire(time.Now(), true, p, "") }
}

func (r capturedReader) LocalEndpoint() string { return r.local }

func (r capturedReader) TargetIdentity() string { return r.targetID }

func (r capturedReader) CaptureBackend() string { return r.backend }
func (r capturedReader) CaptureService() string { return r.service }
