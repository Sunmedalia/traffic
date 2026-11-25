package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type evidenceBackpressurePolicy string

const (
	evidenceBackpressureStrict evidenceBackpressurePolicy = "strict"
	evidenceBackpressureDrop   evidenceBackpressurePolicy = "drop"
)

const (
	evidenceMaxRecordBytes              = 4 << 20
	evidenceDefaultDataBudget           = 4 << 20
	evidenceDefaultControlBudget        = 1 << 20
	evidenceDefaultDataSlots            = 2048
	evidenceDefaultControlSlots         = 2048
	evidenceDefaultGlobalDataBudget     = 32 << 20
	evidenceDefaultGlobalControlReserve = 4 << 20
	evidenceBufferSize                  = 256 << 10
)

var evidenceBackpressure = string(evidenceBackpressureStrict)

var (
	errEvidenceBackpressure    = errors.New("raw evidence queue exhausted; capture stopped")
	errEvidenceControlOverflow = fmt.Errorf("%w: control reserve exhausted", errEvidenceBackpressure)
	errEvidenceEventShed       = errors.New("raw evidence data event shed due to queue congestion")
	errEvidenceNoSpace         = errors.New("raw evidence storage exhausted (ENOSPC)")
	errEvidenceIO              = errors.New("raw evidence I/O error (EIO)")
	errEvidenceWriteFailure    = errors.New("raw evidence sink failure")
	errEvidenceDrainTimeout    = errors.New("raw evidence drain timed out")
)

func parseEvidenceBackpressurePolicy(value string) (evidenceBackpressurePolicy, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "strict", "stop":
		return evidenceBackpressureStrict, nil
	case "drop", "shed":
		return evidenceBackpressureDrop, nil
	default:
		return "", fmt.Errorf("invalid --evidence-backpressure policy %q; expected strict or drop", value)
	}
}

func isEvidenceNoSpace(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errEvidenceNoSpace) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return true
	}
	if runtime.GOOS == "windows" {
		// Win32 ERROR_DISK_FULL (112) and ERROR_HANDLE_DISK_FULL (39).
		if errors.Is(err, syscall.Errno(112)) || errors.Is(err, syscall.Errno(39)) {
			return true
		}
	}
	return false
}

func isEvidenceIOError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errEvidenceIO) || errors.Is(err, syscall.EIO) {
		return true
	}
	if runtime.GOOS == "windows" {
		// Win32 ERROR_IO_DEVICE (1117), ERROR_WRITE_FAULT (29), ERROR_CRC (23).
		if errors.Is(err, syscall.Errno(1117)) || errors.Is(err, syscall.Errno(29)) || errors.Is(err, syscall.Errno(23)) {
			return true
		}
	}
	return false
}

func isEvidenceCongestion(err error) bool {
	return errors.Is(err, errEvidenceBackpressure) || errors.Is(err, errEvidenceEventShed)
}

func classifyEvidenceSinkError(backend string, err error) (error, string) {
	if err == nil {
		return nil, ""
	}
	switch {
	case isEvidenceNoSpace(err):
		if errors.Is(err, errEvidenceNoSpace) {
			return err, "evidence_write_enospc"
		}
		return fmt.Errorf("%s raw evidence: %w: %w", backend, errEvidenceNoSpace, err), "evidence_write_enospc"
	case isEvidenceIOError(err):
		if errors.Is(err, errEvidenceIO) {
			return err, "evidence_write_eio"
		}
		return fmt.Errorf("%s raw evidence: %w: %w", backend, errEvidenceIO, err), "evidence_write_eio"
	default:
		if errors.Is(err, errEvidenceWriteFailure) {
			return err, "evidence_write_error"
		}
		return fmt.Errorf("%s raw evidence: %w: %w", backend, errEvidenceWriteFailure, err), "evidence_write_error"
	}
}

type evidenceSink interface {
	io.Writer
	Sync() error
	Close() error
}

type evidenceItem struct {
	data    []byte
	control bool
}

type evidenceWriterConfig struct {
	policy               evidenceBackpressurePolicy
	dataBudget           int
	controlBudget        int
	dataSlots            int
	controlSlots         int
	globalDataBudget     uint64
	globalControlReserve uint64
	timeout              time.Duration
}

func defaultEvidenceWriterConfig(policy evidenceBackpressurePolicy) evidenceWriterConfig {
	if policy == "" {
		policy = evidenceBackpressureStrict
	}
	return evidenceWriterConfig{
		policy:               policy,
		dataBudget:           evidenceDefaultDataBudget,
		controlBudget:        evidenceDefaultControlBudget,
		dataSlots:            evidenceDefaultDataSlots,
		controlSlots:         evidenceDefaultControlSlots,
		globalDataBudget:     evidenceDefaultGlobalDataBudget,
		globalControlReserve: evidenceDefaultGlobalControlReserve,
		timeout:              drainTimeout,
	}
}

type evidenceWriter struct {
	store                *Store
	sink                 evidenceSink
	backend              string
	policy               evidenceBackpressurePolicy
	dataBudget           int
	controlBudget        int
	dataSlots            int
	controlSlots         int
	globalDataBudget     uint64
	globalControlReserve uint64
	queue                chan evidenceItem
	done                 chan struct{}
	mu                   sync.Mutex
	closeOnce            sync.Once
	timeoutOnce          sync.Once
	closed               bool
	dataPending          int
	controlPending       int
	dataQueued           int
	controlQueued        int
	shedding             bool
	congested            atomic.Bool
	failed               atomic.Bool
	shedEvents           uint64
	reportedShed         uint64
	err                  error
	timeout              time.Duration
}

func newEvidenceWriter(s *Store, sink evidenceSink, backend string) *evidenceWriter {
	return newEvidenceWriterWithPolicy(s, sink, backend, evidenceBackpressureStrict)
}

func newEvidenceWriterWithPolicy(s *Store, sink evidenceSink, backend string, policy evidenceBackpressurePolicy) *evidenceWriter {
	return newEvidenceWriterWithConfig(s, sink, backend, defaultEvidenceWriterConfig(policy))
}

func newEvidenceWriterWithConfig(s *Store, sink evidenceSink, backend string, cfg evidenceWriterConfig) *evidenceWriter {
	if cfg.policy == "" {
		cfg.policy = evidenceBackpressureStrict
	}
	if cfg.dataBudget <= 0 {
		cfg.dataBudget = evidenceDefaultDataBudget
	}
	if cfg.controlBudget <= 0 {
		cfg.controlBudget = evidenceDefaultControlBudget
	}
	if cfg.dataSlots <= 0 {
		cfg.dataSlots = evidenceDefaultDataSlots
	}
	if cfg.controlSlots <= 0 {
		cfg.controlSlots = evidenceDefaultControlSlots
	}
	if cfg.globalDataBudget == 0 {
		cfg.globalDataBudget = evidenceDefaultGlobalDataBudget
	}
	if cfg.globalControlReserve == 0 {
		cfg.globalControlReserve = evidenceDefaultGlobalControlReserve
	}
	if cfg.timeout <= 0 {
		cfg.timeout = drainTimeout
	}
	// A 100 ms CPU quota interval can deliver hundreds of small probe events
	// in one burst. Share one FIFO channel across data and control records so
	// source/loss/end control markers retain both a dedicated reserve and exact
	// serialization order relative to surrounding data records.
	queueCap := cfg.dataSlots
	if cfg.policy == evidenceBackpressureDrop {
		queueCap += cfg.controlSlots
	}
	w := &evidenceWriter{
		store:                s,
		sink:                 sink,
		backend:              backend,
		policy:               cfg.policy,
		dataBudget:           cfg.dataBudget,
		controlBudget:        cfg.controlBudget,
		dataSlots:            cfg.dataSlots,
		controlSlots:         cfg.controlSlots,
		globalDataBudget:     cfg.globalDataBudget,
		globalControlReserve: cfg.globalControlReserve,
		queue:                make(chan evidenceItem, queueCap),
		done:                 make(chan struct{}),
		timeout:              cfg.timeout,
	}
	s.mu.Lock()
	s.stats.RawEvidenceWriters++
	s.mu.Unlock()
	go w.run()
	return w
}

func (w *evidenceWriter) failure() error {
	if !w.failed.Load() {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *evidenceWriter) Write(data []byte) (int, error) {
	accepted, err := w.writeData(data)
	if err != nil {
		return 0, err
	}
	if !accepted {
		return 0, errEvidenceEventShed
	}
	return len(data), nil
}

type evidencePending uint64

func packEvidencePending(data, control uint64) evidencePending {
	return evidencePending(data<<32 | control)
}

func (p evidencePending) data() uint64    { return uint64(p >> 32) }
func (p evidencePending) control() uint64 { return uint64(uint32(p)) }
func (p evidencePending) total() uint64   { return p.data() + p.control() }

func (s *Store) reserveEvidence(previous evidencePending, data, control uint64) bool {
	next := packEvidencePending(data, control)
	if !s.rawEvidencePending.CompareAndSwap(uint64(previous), uint64(next)) {
		return false
	}
	for total, high := next.total(), s.rawEvidenceHighWater.Load(); total > high; high = s.rawEvidenceHighWater.Load() {
		if s.rawEvidenceHighWater.CompareAndSwap(high, total) {
			break
		}
	}
	return true
}

func (w *evidenceWriter) dataDrainedLocked(globalDataPending uint64) bool {
	return w.dataPending <= w.dataBudget/2 && w.dataQueued <= w.dataSlots/2 && globalDataPending <= w.globalDataBudget/2
}

// noteShedLocked accounts for one complete shed data event under w.mu and
// returns an immediate gap delta on episode start so GapCounts reflects active
// congestion right away without writing one gaps.jsonl line per dropped event.
func (w *evidenceWriter) noteShedLocked(episodeStart bool) uint64 {
	w.shedEvents++
	w.store.rawEvidenceQueueDropped.Add(1)
	if episodeStart && w.shedEvents > w.reportedShed {
		delta := w.shedEvents - w.reportedShed
		w.reportedShed = w.shedEvents
		return delta
	}
	return 0
}

func (w *evidenceWriter) takeUnreportedShedLocked() uint64 {
	if w.shedEvents <= w.reportedShed {
		return 0
	}
	delta := w.shedEvents - w.reportedShed
	w.reportedShed = w.shedEvents
	return delta
}

func (w *evidenceWriter) flushShedGap() {
	w.mu.Lock()
	delta := w.takeUnreportedShedLocked()
	w.mu.Unlock()
	if delta > 0 {
		w.store.gap(w.backend, "", "evidence_queue_shed", "events", delta)
	}
}

func (w *evidenceWriter) enqueueLocked(data []byte, control, owned bool) {
	if !owned {
		data = bytes.Clone(data)
	}
	if control {
		w.controlPending += len(data)
		w.controlQueued++
	} else {
		w.dataPending += len(data)
		w.dataQueued++
	}
	w.queue <- evidenceItem{data: data, control: control}
}

func (w *evidenceWriter) enqueueStrictLocked(data []byte, control, owned bool) (string, error) {
	totalPending := w.dataPending + w.controlPending
	totalQueued := w.dataQueued + w.controlQueued
	if len(data) > evidenceMaxRecordBytes || len(data) > w.dataBudget || totalPending+len(data) > w.dataBudget || totalQueued >= w.dataSlots {
		w.setFailureLocked(errEvidenceBackpressure)
		return "evidence_queue_overflow", errEvidenceBackpressure
	}
	for {
		pending := evidencePending(w.store.rawEvidencePending.Load())
		dataBytes, controlBytes := pending.data(), pending.control()
		if control {
			controlBytes += uint64(len(data))
		} else {
			dataBytes += uint64(len(data))
		}
		if dataBytes+controlBytes > w.globalDataBudget || dataBytes > math.MaxUint32 || controlBytes > math.MaxUint32 {
			w.setFailureLocked(errEvidenceBackpressure)
			return "evidence_global_budget", errEvidenceBackpressure
		}
		if w.store.reserveEvidence(pending, dataBytes, controlBytes) {
			break
		}
	}
	w.enqueueLocked(data, control, owned)
	return "", nil
}

// Callers of the owned write methods relinquish their buffers on entry.
func (w *evidenceWriter) writeOwnedControl(data []byte) error {
	return w.writeControlWithOwnership(data, true)
}

func (w *evidenceWriter) writeControl(data []byte) error {
	return w.writeControlWithOwnership(data, false)
}

func (w *evidenceWriter) writeControlWithOwnership(data []byte, owned bool) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return io.ErrClosedPipe
	}
	if w.err != nil {
		err := w.err
		w.mu.Unlock()
		return err
	}
	if w.policy != evidenceBackpressureDrop {
		reason, err := w.enqueueStrictLocked(data, true, owned)
		w.mu.Unlock()
		if err != nil {
			w.store.gap(w.backend, "", reason, "writes", 1)
			w.store.fail(err)
		}
		return err
	}
	if len(data) > evidenceMaxRecordBytes || len(data) > w.controlBudget || w.controlPending+len(data) > w.controlBudget || w.controlQueued >= w.controlSlots {
		w.setFailureLocked(errEvidenceControlOverflow)
		w.mu.Unlock()
		w.store.gap(w.backend, "", "evidence_control_overflow", "writes", 1)
		w.store.fail(errEvidenceControlOverflow)
		return errEvidenceControlOverflow
	}
	for {
		pending := evidencePending(w.store.rawEvidencePending.Load())
		control := pending.control() + uint64(len(data))
		if control > min(w.globalControlReserve, math.MaxUint32) ||
			pending.data()+control > w.globalDataBudget+w.globalControlReserve {
			w.setFailureLocked(errEvidenceControlOverflow)
			w.mu.Unlock()
			w.store.gap(w.backend, "", "evidence_control_overflow", "writes", 1)
			w.store.fail(errEvidenceControlOverflow)
			return errEvidenceControlOverflow
		}
		if w.store.reserveEvidence(pending, pending.data(), control) {
			break
		}
	}
	w.enqueueLocked(data, true, owned)
	w.mu.Unlock()
	return nil
}

// dataDropLocked checks the data budget without reserving any bytes. An
// oversized event does not start persistent shedding in a drained queue.
func (w *evidenceWriter) dataDropLocked(size int, pending evidencePending) (shed bool, gapDelta uint64) {
	if size > evidenceMaxRecordBytes || size > w.dataBudget {
		started := !w.shedding
		if w.dataPending > w.dataBudget/2 || w.dataQueued > w.dataSlots/2 {
			w.shedding = true
			w.congested.Store(true)
		}
		return true, w.noteShedLocked(started)
	}
	if w.shedding && !w.dataDrainedLocked(pending.data()) {
		return true, w.noteShedLocked(false)
	}
	if w.dataPending+size > w.dataBudget || w.dataQueued >= w.dataSlots ||
		pending.data()+uint64(size) > min(w.globalDataBudget, math.MaxUint32) ||
		pending.total()+uint64(size) > w.globalDataBudget+w.globalControlReserve {
		started := !w.shedding
		w.shedding = true
		w.congested.Store(true)
		return true, w.noteShedLocked(started)
	}
	return false, 0
}

// shedBeforeEncoding checks a lower bound. Exact encoded sizes are still
// checked at commit, when other writers may have changed the global budget.
func (w *evidenceWriter) shedBeforeEncoding(minSize int) (bool, error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return false, io.ErrClosedPipe
	}
	if w.err != nil || w.policy != evidenceBackpressureDrop {
		err := w.err
		w.mu.Unlock()
		return false, err
	}
	shed, delta := w.dataDropLocked(minSize, evidencePending(w.store.rawEvidencePending.Load()))
	w.mu.Unlock()
	if delta > 0 {
		w.store.gap(w.backend, "", "evidence_queue_shed", "events", delta)
	}
	return shed, nil
}

func (w *evidenceWriter) checkAndReserveDataDropLocked(lossData, eventData []byte, owned bool) (accepted bool, gapDelta uint64, controlErr error) {
	for {
		pending := evidencePending(w.store.rawEvidencePending.Load())
		if shed, delta := w.dataDropLocked(len(eventData), pending); shed {
			return false, delta, nil
		}
		data := pending.data() + uint64(len(eventData))
		control := pending.control() + uint64(len(lossData))
		if len(lossData) > 0 &&
			(len(lossData) > evidenceMaxRecordBytes || len(lossData) > w.controlBudget ||
				w.controlPending+len(lossData) > w.controlBudget || w.controlQueued >= w.controlSlots ||
				control > min(w.globalControlReserve, math.MaxUint32) || data+control > w.globalDataBudget+w.globalControlReserve) {
			w.setFailureLocked(errEvidenceControlOverflow)
			return false, 0, errEvidenceControlOverflow
		}
		if w.store.reserveEvidence(pending, data, control) {
			break
		}
	}
	w.shedding = false
	w.congested.Store(false)
	if len(lossData) > 0 {
		w.enqueueLocked(lossData, true, owned)
	}
	w.enqueueLocked(eventData, false, owned)
	return true, w.takeUnreportedShedLocked(), nil
}

func (w *evidenceWriter) writeData(data []byte) (bool, error) {
	return w.writeDataWithOwnership(data, false)
}

func (w *evidenceWriter) writeOwnedData(data []byte) (bool, error) {
	return w.writeDataWithOwnership(data, true)
}

func (w *evidenceWriter) writeDataWithOwnership(data []byte, owned bool) (bool, error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return false, io.ErrClosedPipe
	}
	if w.err != nil {
		err := w.err
		w.mu.Unlock()
		return false, err
	}
	if w.policy != evidenceBackpressureDrop {
		reason, err := w.enqueueStrictLocked(data, false, owned)
		w.mu.Unlock()
		if err != nil {
			w.store.gap(w.backend, "", reason, "writes", 1)
			w.store.fail(err)
			return false, err
		}
		return true, nil
	}
	accepted, gapDelta, controlErr := w.checkAndReserveDataDropLocked(nil, data, owned)
	w.mu.Unlock()
	if controlErr != nil {
		w.store.gap(w.backend, "", "evidence_control_overflow", "writes", 1)
		w.store.fail(controlErr)
		return false, controlErr
	}
	if gapDelta > 0 {
		w.store.gap(w.backend, "", "evidence_queue_shed", "events", gapDelta)
	}
	return accepted, nil
}

// writeOwnedRecoveryAndData atomically enqueues a preceding loss control record and
// the recovered data event into the same FIFO queue once the data budget can
// accept the event, preventing any post-gap data from overtaking its loss marker.
func (w *evidenceWriter) writeOwnedRecoveryAndData(lossData, eventData []byte) (bool, error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return false, io.ErrClosedPipe
	}
	if w.err != nil {
		err := w.err
		w.mu.Unlock()
		return false, err
	}
	if w.policy != evidenceBackpressureDrop {
		reason, err := w.enqueueStrictLocked(lossData, true, true)
		if err == nil {
			reason, err = w.enqueueStrictLocked(eventData, false, true)
		}
		w.mu.Unlock()
		if err != nil {
			w.store.gap(w.backend, "", reason, "writes", 1)
			w.store.fail(err)
			return false, err
		}
		return true, nil
	}
	accepted, gapDelta, controlErr := w.checkAndReserveDataDropLocked(lossData, eventData, true)
	w.mu.Unlock()
	if controlErr != nil {
		w.store.gap(w.backend, "", "evidence_control_overflow", "writes", 1)
		w.store.fail(controlErr)
		return false, controlErr
	}
	if gapDelta > 0 {
		w.store.gap(w.backend, "", "evidence_queue_shed", "events", gapDelta)
	}
	return accepted, nil
}

func (w *evidenceWriter) release(dataBytes, controlBytes, dataItems, controlItems int) {
	w.mu.Lock()
	dataBytes = min(dataBytes, w.dataPending)
	controlBytes = min(controlBytes, w.controlPending)
	dataItems = min(dataItems, w.dataQueued)
	controlItems = min(controlItems, w.controlQueued)
	w.dataPending -= dataBytes
	w.controlPending -= controlBytes
	w.dataQueued -= dataItems
	w.controlQueued -= controlItems
	for {
		pending := evidencePending(w.store.rawEvidencePending.Load())
		data := pending.data() - min(pending.data(), uint64(dataBytes))
		control := pending.control() - min(pending.control(), uint64(controlBytes))
		if w.store.rawEvidencePending.CompareAndSwap(uint64(pending), uint64(packEvidencePending(data, control))) {
			break
		}
	}
	w.mu.Unlock()
}

func (w *evidenceWriter) setFailureLocked(err error) {
	w.err = err
	w.failed.Store(true)
}

func (w *evidenceWriter) recordHardFailure(err error) (error, string) {
	classified, reason := classifyEvidenceSinkError(w.backend, err)
	w.mu.Lock()
	if w.err == nil || isEvidenceCongestion(w.err) {
		w.setFailureLocked(classified)
	}
	w.mu.Unlock()
	return classified, reason
}

func (w *evidenceWriter) run() {
	var runErr error
	var hardReason string
	var flushedUnsynced uint64
	fail := func(err error) {
		hardErr, reason := w.recordHardFailure(err)
		hardReason = reason
		w.store.mu.Lock()
		w.store.stats.RawEvidenceDrainUnconfirmed = true
		w.store.mu.Unlock()
		w.store.fail(hardErr)
	}
	defer func() {
		if runErr != nil {
			fail(runErr)
		}
		if err := w.sink.Close(); runErr == nil && err != nil {
			runErr = err
			fail(runErr)
		}
		w.mu.Lock()
		remainingData := w.dataPending
		remainingControl := w.controlPending
		remainingDataItems := w.dataQueued
		remainingControlItems := w.controlQueued
		remaining := remainingData + remainingControl
		shedDelta := w.takeUnreportedShedLocked()
		w.mu.Unlock()
		w.release(remainingData, remainingControl, remainingDataItems, remainingControlItems)
		w.store.mu.Lock()
		w.store.stats.RawEvidenceWriters--
		w.store.mu.Unlock()
		if shedDelta > 0 {
			w.store.gap(w.backend, "", "evidence_queue_shed", "events", shedDelta)
		}
		if runErr != nil {
			w.store.gap(w.backend, "", hardReason, "errors", 1)
			w.store.gap(w.backend, "", "evidence_write_unconfirmed", "bytes", uint64(remaining)+flushedUnsynced)
		}
		close(w.done)
	}()
	writer := bufio.NewWriterSize(w.sink, evidenceBufferSize)
	bufferedData, bufferedControl := 0, 0
	bufferedDataItems, bufferedControlItems := 0, 0
	flush := func() error {
		if err := writer.Flush(); err != nil {
			return err
		}
		if bufferedData > 0 || bufferedControl > 0 || bufferedDataItems > 0 || bufferedControlItems > 0 {
			flushedUnsynced += uint64(bufferedData + bufferedControl)
			w.release(bufferedData, bufferedControl, bufferedDataItems, bufferedControlItems)
			bufferedData, bufferedControl = 0, 0
			bufferedDataItems, bufferedControlItems = 0, 0
		}
		return nil
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case item, ok := <-w.queue:
			if !ok {
				runErr = flush()
				if runErr == nil {
					runErr = w.sink.Sync()
					if runErr == nil {
						flushedUnsynced = 0
					}
				}
				return
			}
			if _, runErr = writer.Write(item.data); runErr != nil {
				return
			}
			if item.control {
				bufferedControl += len(item.data)
				bufferedControlItems++
			} else {
				bufferedData += len(item.data)
				bufferedDataItems++
			}
			if bufferedData+bufferedControl >= evidenceBufferSize || (len(w.queue) == 0 && w.congested.Load()) {
				if runErr = flush(); runErr != nil {
					return
				}
			}
		case <-ticker.C:
			w.flushShedGap()
			if runErr = flush(); runErr != nil {
				return
			}
		}
	}
}

func (w *evidenceWriter) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		close(w.queue)
		w.mu.Unlock()
	})
	select {
	case <-w.done:
		w.flushShedGap()
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.err
	case <-time.After(w.timeout):
		w.timeoutOnce.Do(func() {
			w.flushShedGap()
			err := fmt.Errorf("%s raw evidence drain exceeded %s: %w", w.backend, w.timeout, errEvidenceDrainTimeout)
			w.mu.Lock()
			if w.err == nil {
				w.setFailureLocked(err)
			}
			w.mu.Unlock()
			w.store.mu.Lock()
			w.store.stats.RawEvidenceDrainUnconfirmed = true
			w.store.mu.Unlock()
			w.store.fail(err)
			w.store.gap(w.backend, "", "evidence_drain_timeout", "shutdowns", 1)
		})
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.err
	}
}
