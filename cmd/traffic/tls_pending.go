package main

import (
	"bytes"
	"context"
	"sync"
	"time"
)

type frameContext struct {
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
}

func (r capturedReader) CaptureTime() time.Time { return r.captured }

// ingest serializes frame bookkeeping with the idle-expiry worker. HTTP parsing
// and storage happen outside the frame mutex.
func (f *Frames) ingest(key string, payload []byte, meta frameContext, head bool, p *HTTPProcessor) {
	now := time.Now().UTC()
	f.mu.Lock()
	if f.contexts == nil {
		f.contexts = make(map[string]frameContext)
	}
	if previous, ok := f.contexts[key]; ok {
		meta.first = previous.first
	} else {
		meta.first = now
	}
	meta.updated = now
	chunks, gap := f.feed(key, payload, head)
	gap = gap || meta.incomplete
	if len(f.buffers[key]) > 0 {
		f.contexts[key] = meta
	} else {
		delete(f.contexts, key)
	}
	for existing := range f.contexts {
		if len(f.buffers[existing]) == 0 {
			delete(f.contexts, existing)
		}
	}
	f.mu.Unlock()
	if gap {
		p.s.mu.Lock()
		p.s.stats.TLSDropped++
		p.s.mu.Unlock()
	}
	for _, chunk := range chunks {
		p.process(capturedReader{bytes.NewReader(chunk), meta.first, meta.local}, "tls:"+meta.connection, meta.client, "tls-hook", meta.pid, gap)
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
		if (connection == "" || meta.connection == connection) && (all || now.Sub(meta.updated) >= time.Minute) {
			expired = append(expired, partial{f.buffers[key], meta})
			delete(f.buffers, key)
			delete(f.contexts, key)
		}
	}
	f.mu.Unlock()
	for _, item := range expired {
		if len(item.data) == 0 {
			continue
		}
		if !bytes.Contains(item.data, []byte("\r\n\r\n")) && !bytes.Contains(item.data, []byte("\n\n")) {
			record := Transaction{LocalEndpoint: item.meta.local, Time: item.meta.first, Source: "tls-hook-fragment", Client: item.meta.client, Connection: "tls:" + item.meta.connection, PID: item.meta.pid, Request: item.data, Incomplete: true}
			if err := p.s.save(record); err != nil {
				p.s.fail(err)
			}
			continue
		}
		p.process(capturedReader{bytes.NewReader(item.data), item.meta.first, item.meta.local}, "tls:"+item.meta.connection, item.meta.client, "tls-hook", item.meta.pid, true)
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
