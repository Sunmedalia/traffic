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

const evidenceShedLossReason = "evidence_queue_shed"

type sourceRecordState struct {
	backend     string
	target      session.Target
	pendingLoss uint64
}

type eventRecorder struct {
	mu         sync.Mutex
	store      *Store
	policy     evidenceBackpressurePolicy
	writer     *evidenceWriter
	writerCfg  *evidenceWriterConfig
	customSink evidenceSink
	initErr    error
	sources    map[string]*sourceRecordState
	closed     bool
}

func newRecorder(s *Store) *eventRecorder {
	return newRecorderWithPolicy(s, evidenceBackpressureStrict)
}

func newRecorderWithPolicy(s *Store, policy evidenceBackpressurePolicy) *eventRecorder {
	if policy == "" {
		policy = evidenceBackpressureStrict
	}
	return &eventRecorder{
		store:   s,
		policy:  policy,
		sources: map[string]*sourceRecordState{},
	}
}

func isControlRawEvent(event session.RawEvent) bool {
	switch event.Type {
	case "source", "loss", "end":
		return true
	case "iis":
		return event.IIS != nil && event.IIS.Type == "loss"
	default:
		return false
	}
}

func marshalRawEventLine(event session.RawEvent) ([]byte, error) {
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func (r *eventRecorder) ensureWriterLocked() error {
	if r.writer != nil {
		return nil
	}
	sink := r.customSink
	if sink == nil {
		dir := filepath.Join(r.store.dir, "tls")
		if err := os.MkdirAll(dir, 0700); err != nil {
			hardErr, reason := classifyEvidenceSinkError("raw-tls", err)
			r.store.fail(hardErr)
			r.store.gap("raw-tls", "", reason, "errors", 1)
			return hardErr
		}
		file, err := os.OpenFile(filepath.Join(dir, "stream.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			hardErr, reason := classifyEvidenceSinkError("raw-tls", err)
			r.store.fail(hardErr)
			r.store.gap("raw-tls", "", reason, "errors", 1)
			return hardErr
		}
		sink = file
	}
	cfg := defaultEvidenceWriterConfig(r.policy)
	if r.writerCfg != nil {
		cfg = *r.writerCfg
		if cfg.policy == "" {
			cfg.policy = r.policy
		}
	}
	r.writer = newEvidenceWriterWithConfig(r.store, sink, "raw-tls", cfg)
	return nil
}

func (r *eventRecorder) flushSourceLossLocked(source string, state *sourceRecordState, at time.Time) error {
	if state == nil || state.pendingLoss == 0 {
		return nil
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	lossBytes, err := marshalRawEventLine(session.RawEvent{
		Version: 1,
		Time:    at,
		Source:  source,
		Type:    "loss",
		Reason:  evidenceShedLossReason,
		Unit:    "events",
		Count:   state.pendingLoss,
	})
	if err != nil {
		return err
	}
	if err := r.writer.writeControl(lossBytes); err != nil {
		return err
	}
	state.pendingLoss = 0
	return nil
}

func (r *eventRecorder) record(source, backend string, target session.Target, event session.RawEvent) error {
	_, err := r.recordOutcome(source, backend, target, event)
	return err
}

func (r *eventRecorder) recordOutcome(source, backend string, target session.Target, event session.RawEvent) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recordOutcomeLocked(source, backend, target, event)
}

func (r *eventRecorder) recordOutcomeLocked(source, backend string, target session.Target, event session.RawEvent) (bool, error) {
	if r.closed {
		return false, fmt.Errorf("raw event recorder closed")
	}
	if r.initErr != nil {
		return false, r.initErr
	}
	if err := r.ensureWriterLocked(); err != nil {
		r.initErr = err
		return false, err
	}
	if err := r.writer.failure(); err != nil {
		return false, err
	}
	now := time.Now().UTC()
	event.Version, event.Source = 1, source
	if event.Time.IsZero() {
		event.Time = now
	} else {
		event.Time = event.Time.UTC()
	}
	eventBytes, err := marshalRawEventLine(event)
	if err != nil {
		return false, err
	}
	state := r.sources[source]
	if state == nil {
		if len(r.sources) >= 1024 {
			return false, fmt.Errorf("too many active probe sources")
		}
		sourceBytes, err := marshalRawEventLine(session.RawEvent{
			Version: 1,
			Time:    now,
			Source:  source,
			Backend: backend,
			Type:    "source",
			Target:  &target,
		})
		if err != nil {
			return false, err
		}
		if err := r.writer.writeControl(sourceBytes); err != nil {
			return false, err
		}
		state = &sourceRecordState{backend: backend, target: target}
		r.sources[source] = state
		if event.Type == "source" {
			return true, nil
		}
	} else if event.Type == "source" {
		return false, fmt.Errorf("duplicate raw TLS source generation %q", source)
	}
	if isControlRawEvent(event) {
		if err := r.flushSourceLossLocked(source, state, event.Time); err != nil {
			return false, err
		}
		if err := r.writer.writeControl(eventBytes); err != nil {
			return false, err
		}
		if event.Type == "end" {
			delete(r.sources, source)
		}
		return true, nil
	}
	var accepted bool
	if state.pendingLoss > 0 {
		lossBytes, err := marshalRawEventLine(session.RawEvent{
			Version: 1,
			Time:    event.Time,
			Source:  source,
			Type:    "loss",
			Reason:  evidenceShedLossReason,
			Unit:    "events",
			Count:   state.pendingLoss,
		})
		if err != nil {
			return false, err
		}
		accepted, err = r.writer.writeRecoveryAndData(lossBytes, eventBytes)
		if err != nil {
			return false, err
		}
		if accepted {
			state.pendingLoss = 0
		} else {
			state.pendingLoss++
		}
	} else {
		accepted, err = r.writer.writeData(eventBytes)
		if err != nil {
			return false, err
		}
		if !accepted {
			state.pendingLoss++
		}
	}
	if accepted && r.store != nil && (event.Type == "data" || (event.Type == "iis" && event.IIS != nil && (event.IIS.Type == "request" || event.IIS.Type == "response"))) {
		r.store.noteTLSEvent(event.Time)
	}
	return accepted, nil
}

func (r *eventRecorder) close() error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		if r.writer != nil && r.writer.failure() == nil {
			sources := make([]string, 0, len(r.sources))
			for source := range r.sources {
				sources = append(sources, source)
			}
			sort.Strings(sources)
			now := time.Now().UTC()
			for _, source := range sources {
				_ = r.flushSourceLossLocked(source, r.sources[source], now)
			}
		}
	}
	writer := r.writer
	initErr := r.initErr
	r.mu.Unlock()
	if writer != nil {
		return writer.Close()
	}
	return initErr
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
	truncatedBytes := uint64(0)
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
		if event.OriginalLength > len(event.Data) {
			truncatedBytes = uint64(event.OriginalLength - len(event.Data))
			event.Incomplete = true
		}
	}
	reason := ""
	if event.Type == "loss" {
		reason = "probe_queue_loss"
		r.store.gap(backend, target.ID, "probe_queue_loss", "events", event.Count)
		r.store.mu.Lock()
		r.store.stats.TLSDropped += event.Count
		r.store.mu.Unlock()
	}
	accepted, err := r.recordOutcome(source, backend, target, session.RawEvent{
		Type:           event.Type,
		Connection:     event.Connection,
		Direction:      event.Direction,
		Local:          event.Local,
		Client:         event.Client,
		Data:           event.Data,
		Incomplete:     event.Incomplete,
		OriginalLength: event.OriginalLength,
		Count:          event.Count,
		Reason:         reason,
	})
	if err != nil {
		return err
	}
	if accepted && truncatedBytes > 0 {
		r.store.gap(backend, target.ID, "single_call_truncated", "bytes", truncatedBytes)
	}
	return nil
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
	defer r.mu.Unlock()
	var sources []string
	for source := range r.sources {
		if strings.HasPrefix(source, generation+"/") {
			sources = append(sources, source)
		}
	}
	sort.Strings(sources)
	for _, source := range sources {
		state := r.sources[source]
		if state == nil {
			continue
		}
		if _, err := r.recordOutcomeLocked(source, state.backend, state.target, event); err != nil {
			return err
		}
		// A transport-wide count belongs to the whole boundary, not each PID.
		event.Count = 0
	}
	return nil
}

// Observe only successfully queued raw requests. Shed requests during bounded
// backpressure never satisfy --require-plaintext, and final writer failures
// remain fatal.
func (r *eventRecorder) iis(source string, target session.Target, event iisEvent) error {
	accepted, err := r.recordOutcome(source, "iis", target, session.RawEvent{Type: "iis", Time: event.Time, IIS: &event})
	if err != nil {
		return err
	}
	if accepted && event.Type == "request" {
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
