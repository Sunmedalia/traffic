package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

type opensslEvent = session.OpenSSLEvent
type iisEvent = session.IISEvent

type eventRecorder struct {
	mu      sync.Mutex
	store   *Store
	writer  *evidenceWriter
	encoder *json.Encoder
	sources map[string]bool
	closed  bool
}

func newRecorder(s *Store) *eventRecorder {
	return &eventRecorder{store: s, sources: map[string]bool{}}
}

func (r *eventRecorder) record(source, backend string, target session.Target, event session.RawEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("raw event recorder closed")
	}
	if r.encoder == nil {
		dir := filepath.Join(r.store.dir, "tls")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		file, err := os.OpenFile(filepath.Join(dir, "stream.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		r.writer = newEvidenceWriter(r.store, file, "raw-tls")
		r.encoder = json.NewEncoder(r.writer)
	}
	now := time.Now().UTC()
	if !r.sources[source] {
		if len(r.sources) >= 1024 {
			return fmt.Errorf("too many active probe sources")
		}
		if err := r.encoder.Encode(session.RawEvent{Version: 1, Time: now, Source: source, Backend: backend, Type: "source", Target: &target}); err != nil {
			return err
		}
		r.sources[source] = true
	}
	event.Version, event.Source = 1, source
	if event.Time.IsZero() {
		event.Time = now
	}
	err := r.encoder.Encode(event)
	if err == nil {
		if r.store != nil && (event.Type == "data" || (event.Type == "iis" && event.IIS != nil && (event.IIS.Type == "request" || event.IIS.Type == "response"))) {
			r.store.noteTLSEvent(event.Time)
		}
		if event.Type == "end" {
			delete(r.sources, source)
		}
	}
	return err
}

func (r *eventRecorder) close() error {
	r.mu.Lock()
	r.closed = true
	writer := r.writer
	r.mu.Unlock()
	if writer != nil {
		return writer.Close()
	}
	return nil
}

func (r *eventRecorder) target(pid int, id string) session.Target {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	for _, target := range r.store.stats.Targets {
		if target.PID == pid && (id == "" || target.ID == id) {
			return target
		}
	}
	return session.Target{PID: pid, ID: id, Service: "openssl"}
}

func (r *eventRecorder) openssl(source, backend string, target session.Target, event opensslEvent) error {
	if event.Type == "data" {
		if event.Direction != "read" && event.Direction != "write" {
			return fmt.Errorf("invalid probe direction")
		}
		_, lp, err := net.SplitHostPort(event.Local)
		if err != nil {
			return err
		}
		_, rp, err := net.SplitHostPort(event.Client)
		if err != nil {
			return err
		}
		local, _ := strconv.Atoi(lp)
		remote, _ := strconv.Atoi(rp)
		if !capturePorts[local] && !capturePorts[remote] {
			return nil
		}
	}
	if event.Type == "data" && event.OriginalLength > len(event.Data) {
		r.store.gap(backend, target.ID, "single_call_truncated", "bytes", uint64(event.OriginalLength-len(event.Data)))
		event.Incomplete = true
	}
	reason := ""
	if event.Type == "loss" {
		reason = "probe_queue_loss"
		r.store.gap(backend, target.ID, "probe_queue_loss", "events", event.Count)
		r.store.mu.Lock()
		r.store.stats.TLSDropped += event.Count
		r.store.mu.Unlock()
	}
	return r.record(source, backend, target, session.RawEvent{Type: event.Type, Connection: event.Connection, Direction: event.Direction, Local: event.Local, Client: event.Client, Data: event.Data, Incomplete: event.Incomplete, OriginalLength: event.OriginalLength, Count: event.Count, Reason: reason})
}

func portNumbers(ports map[int]bool) []int {
	result := []int{}
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}
func captureAddresses() []string {
	var result []string
	_ = inCaptureNamespace(func() error {
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}
		for _, a := range addresses {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil {
				result = append(result, ip.String())
			}
		}
		return nil
	})
	return result
}
func (r *eventRecorder) boundary(generation string, event session.RawEvent) error {
	r.mu.Lock()
	var sources []string
	for source := range r.sources {
		if strings.HasPrefix(source, generation+"/") {
			sources = append(sources, source)
		}
	}
	r.mu.Unlock()
	sort.Strings(sources)
	for _, source := range sources {
		if err := r.record(source, "", session.Target{}, event); err != nil {
			return err
		}
		// A transport-wide count belongs to the whole boundary, not each PID.
		event.Count = 0
	}
	return nil
}

// Observe only successfully queued raw requests. Final writer failures remain
// fatal, so hook diagnostics alone can never satisfy --require-plaintext.
func (r *eventRecorder) iis(source string, target session.Target, event iisEvent) error {
	if err := r.record(source, "iis", target, session.RawEvent{Type: "iis", Time: event.Time, IIS: &event}); err != nil {
		return err
	}
	if event.Type == "request" {
		r.store.mu.Lock()
		r.store.stats.PlaintextObserved = true
		r.store.stats.AttachWindowSuspect = false
		r.store.mu.Unlock()
	}
	if event.Type == "probe-gap" {
		kind := event.Kind
		if kind == "" {
			kind = "unknown"
		}
		r.store.noteProbeGap(source, event.Reason, kind, event.Count)
	}
	return nil
}
