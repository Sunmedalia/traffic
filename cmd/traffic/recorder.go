package main

import (
	"encoding/base64"
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
const maxRawEventSources = 1024

type sourceRecordState struct {
	pendingLoss uint64
}

type eventRecorder struct {
	mu         sync.Mutex
	closeOnce  sync.Once
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
		sink = newEvidenceFile(file)
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

func (r *eventRecorder) record(source, backend string, target session.Target, event session.RawEvent) error {
	_, err := r.recordOutcome(source, backend, target, event)
	return err
}

func marshalSourceLoss(source string, count uint64, at time.Time) ([]byte, error) {
	return marshalRawEventLine(session.RawEvent{
		Version: 1, Time: at, Source: source, Type: "loss",
		Reason: evidenceShedLossReason, Unit: "events", Count: count,
	})
}

func rawEventForSource(event session.RawEvent, source string, now time.Time) session.RawEvent {
	event.Version, event.Source = 1, source
	if event.Time.IsZero() {
		event.Time = now
	} else {
		event.Time = event.Time.UTC()
	}
	return event
}

func (r *eventRecorder) recordOutcome(source, backend string, target session.Target, event session.RawEvent) (bool, error) {
	control := isControlRawEvent(event)
	policy := r.policy
	if r.writerCfg != nil && r.writerCfg.policy != "" {
		policy = r.writerCfg.policy
	}
	preflight := policy == evidenceBackpressureDrop && !control

	now := time.Now().UTC()
	event = rawEventForSource(event, source, now)
	var eventBytes, sourceBytes, lossBytes []byte
	var err error
	if !preflight {
		eventBytes, err = marshalRawEventLine(event)
		if err != nil {
			return false, err
		}
	}
	var lossState *sourceRecordState
	var lossCount uint64
	for {
		r.mu.Lock()
		if err := r.readyWriterLocked(); err != nil {
			r.mu.Unlock()
			return false, err
		}
		state := r.sources[source]
		if state == nil && sourceBytes == nil {
			r.mu.Unlock()
			sourceBytes, err = marshalRawEventLine(session.RawEvent{
				Version: 1, Time: now, Source: source, Backend: backend, Type: "source", Target: &target,
			})
			if err != nil {
				return false, err
			}
			continue
		}
		if preflight {
			// Base64 bytes alone are a lower bound on the final JSON line.
			minSize := 1 + base64.StdEncoding.EncodedLen(len(event.Data))
			if event.IIS != nil {
				minSize += base64.StdEncoding.EncodedLen(len(event.IIS.Data))
			}
			shed, err := r.writer.shedBeforeEncoding(minSize)
			if shed && err == nil {
				if state == nil {
					state, err = r.addSourceLocked(source, sourceBytes)
				}
				if err == nil {
					state.pendingLoss++
				}
			}
			r.mu.Unlock()
			if shed || err != nil {
				return false, err
			}
			eventBytes, err = marshalRawEventLine(event)
			if err != nil {
				return false, err
			}
			preflight = false
			continue
		}
		if state == nil {
			state, err = r.addSourceLocked(source, sourceBytes)
			if err != nil || event.Type == "source" {
				r.mu.Unlock()
				return err == nil, err
			}
		} else if event.Type == "source" {
			r.mu.Unlock()
			return false, fmt.Errorf("duplicate raw TLS source generation %q", source)
		}
		// A concurrent record can change the pending loss while it is being
		// serialized. Commit only if the marker still describes this source.
		if state.pendingLoss > 0 && (lossState != state || lossCount != state.pendingLoss) {
			lossState, lossCount = state, state.pendingLoss
			r.mu.Unlock()
			lossBytes, err = marshalSourceLoss(source, lossCount, event.Time)
			if err != nil {
				return false, err
			}
			continue
		}
		accepted, err := r.recordPreparedLocked(state, event, control, eventBytes, lossBytes)
		r.mu.Unlock()
		return accepted, err
	}
}

func (r *eventRecorder) readyWriterLocked() error {
	if r.closed {
		return fmt.Errorf("raw event recorder closed")
	}
	if r.initErr != nil {
		return r.initErr
	}
	if err := r.ensureWriterLocked(); err != nil {
		r.initErr = err
		return err
	}
	return r.writer.failure()
}

func (r *eventRecorder) addSourceLocked(source string, encoded []byte) (*sourceRecordState, error) {
	if len(r.sources) >= maxRawEventSources {
		return nil, fmt.Errorf("too many active probe sources")
	}
	if err := r.writer.writeOwnedControl(encoded); err != nil {
		return nil, err
	}
	state := &sourceRecordState{}
	r.sources[source] = state
	return state, nil
}

func (r *eventRecorder) recordPreparedLocked(state *sourceRecordState, event session.RawEvent, control bool, eventBytes, lossBytes []byte) (bool, error) {
	if control {
		if state.pendingLoss > 0 {
			if err := r.writer.writeOwnedControl(lossBytes); err != nil {
				return false, err
			}
			state.pendingLoss = 0
		}
		if err := r.writer.writeOwnedControl(eventBytes); err != nil {
			return false, err
		}
		if event.Type == "end" {
			delete(r.sources, event.Source)
		}
		return true, nil
	}
	var accepted bool
	var err error
	if state.pendingLoss > 0 {
		accepted, err = r.writer.writeOwnedRecoveryAndData(lossBytes, eventBytes)
	} else {
		accepted, err = r.writer.writeOwnedData(eventBytes)
	}
	if err != nil {
		return false, err
	}
	if !accepted {
		state.pendingLoss++
	} else {
		state.pendingLoss = 0
		if r.store != nil && (event.Type == "data" || (event.Type == "iis" && event.IIS != nil && (event.IIS.Type == "request" || event.IIS.Type == "response"))) {
			r.store.noteTLSEvent(event.Time)
		}
	}
	return accepted, nil
}

func (r *eventRecorder) close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()

		// Closing freezes the source map. Complete its loss records before
		// any caller closes the writer's queue.
		if r.writer == nil || r.writer.failure() != nil {
			return
		}
		sources := make([]string, 0, len(r.sources))
		for source, state := range r.sources {
			if state.pendingLoss > 0 {
				sources = append(sources, source)
			}
		}
		sort.Strings(sources)
		now := time.Now().UTC()
		for _, source := range sources {
			if encoded, err := marshalSourceLoss(source, r.sources[source].pendingLoss, now); err == nil {
				_ = r.writer.writeOwnedControl(encoded)
			}
		}
	})
	if r.writer != nil {
		return r.writer.Close()
	}
	return r.initErr
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
	if accepted && target.Service == "nginx" && backend == "openssl" && event.Type == "data" && len(event.Data) > 0 && !r.store.plaintextObserved.Load() {
		r.store.mu.Lock()
		r.store.stats.PlaintextObserved = true
		r.store.plaintextObserved.Store(true)
		r.store.mu.Unlock()
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
	type boundaryRecord struct {
		source string
		state  *sourceRecordState
		count  uint64
		event  session.RawEvent
		data   []byte
		loss   []byte
	}

	prefix := generation + "/"
	control := isControlRawEvent(event)
	for {
		r.mu.Lock()
		var records []boundaryRecord
		for source, state := range r.sources {
			if strings.HasPrefix(source, prefix) {
				records = append(records, boundaryRecord{source: source, state: state, count: state.pendingLoss})
			}
		}
		r.mu.Unlock()
		if len(records) == 0 {
			return nil
		}

		sort.Slice(records, func(i, j int) bool { return records[i].source < records[j].source })
		now := time.Now().UTC()
		for i := range records {
			record := &records[i]
			record.event = rawEventForSource(event, record.source, now)
			// A transport-wide count belongs to the boundary, not each PID.
			if i > 0 {
				record.event.Count = 0
			}
			var err error
			record.data, err = marshalRawEventLine(record.event)
			if err != nil {
				return err
			}
			if record.count > 0 {
				record.loss, err = marshalSourceLoss(record.source, record.count, record.event.Time)
				if err != nil {
					return err
				}
			}
		}

		r.mu.Lock()
		if err := r.readyWriterLocked(); err != nil {
			r.mu.Unlock()
			return err
		}
		// Preserve the atomic boundary across all sources. Retry if the
		// generation's membership or pending loss changed during encoding.
		active := 0
		for source := range r.sources {
			if strings.HasPrefix(source, prefix) {
				active++
			}
		}
		current := active == len(records)
		for _, record := range records {
			state := r.sources[record.source]
			current = current && state == record.state && state.pendingLoss == record.count
		}
		if !current {
			r.mu.Unlock()
			continue
		}
		for _, record := range records {
			if _, err := r.recordPreparedLocked(record.state, record.event, control, record.data, record.loss); err != nil {
				r.mu.Unlock()
				return err
			}
		}
		r.mu.Unlock()
		return nil
	}
}

// Observe only successfully queued raw requests. Shed requests during bounded
// backpressure never satisfy --require-plaintext, and final writer failures
// remain fatal.
func (r *eventRecorder) iis(source string, target session.Target, event iisEvent) error {
	accepted, err := r.recordOutcome(source, "iis", target, session.RawEvent{Type: "iis", Time: event.Time, IIS: &event})
	if err != nil {
		return err
	}
	if accepted && event.Type == "request" && !r.store.iisPlaintext.Load() {
		r.store.mu.Lock()
		r.store.stats.PlaintextObserved = true
		r.store.stats.AttachWindowSuspect = false
		r.store.plaintextObserved.Store(true)
		r.store.iisPlaintext.Store(true)
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
