package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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
	shedEvents           uint64
	shedBytes            uint64
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

func (w *evidenceWriter) dataDrainedLocked(globalDataPending uint64) bool {
	return w.dataPending <= w.dataBudget/2 && w.dataQueued <= w.dataSlots/2 && globalDataPending <= w.globalDataBudget/2
}

// noteShedLocked accounts for one complete shed data event under w.mu and
// returns an immediate gap delta on episode start so GapCounts reflects active
// congestion right away without writing one gaps.jsonl line per dropped event.
func (w *evidenceWriter) noteShedLocked(size int, episodeStart bool) uint64 {
	w.shedEvents++
	w.shedBytes += uint64(size)
	w.store.mu.Lock()
	w.store.stats.QueueDropped++
	w.store.mu.Unlock()
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

func (w *evidenceWriter) enqueueStrictLocked(data []byte, control bool) (string, error) {
	totalPending := w.dataPending + w.controlPending
	totalQueued := w.dataQueued + w.controlQueued
	if len(data) > evidenceMaxRecordBytes || len(data) > w.dataBudget || totalPending+len(data) > w.dataBudget || totalQueued >= w.dataSlots {
		w.err = errEvidenceBackpressure
		return "evidence_queue_overflow", errEvidenceBackpressure
	}
	w.store.mu.Lock()
	if w.store.stats.RawEvidencePendingBytes+uint64(len(data)) > w.globalDataBudget {
		w.store.mu.Unlock()
		w.err = errEvidenceBackpressure
		return "evidence_global_budget", errEvidenceBackpressure
	}
	w.store.stats.RawEvidencePendingBytes += uint64(len(data))
	if control {
		w.store.rawEvidenceControlPending += uint64(len(data))
	}
	if w.store.stats.RawEvidencePendingBytes > w.store.stats.RawEvidenceHighWaterBytes {
		w.store.stats.RawEvidenceHighWaterBytes = w.store.stats.RawEvidencePendingBytes
	}
	w.store.mu.Unlock()
	copied := append([]byte(nil), data...)
	if control {
		w.controlPending += len(copied)
		w.controlQueued++
	} else {
		w.dataPending += len(copied)
		w.dataQueued++
	}
	w.queue <- evidenceItem{data: copied, control: control}
	return "", nil
}

func (w *evidenceWriter) writeControl(data []byte) error {
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
		reason, err := w.enqueueStrictLocked(data, true)
		w.mu.Unlock()
		if err != nil {
			w.store.gap(w.backend, "", reason, "writes", 1)
			w.store.fail(err)
		}
		return err
	}
	if len(data) > evidenceMaxRecordBytes || len(data) > w.controlBudget || w.controlPending+len(data) > w.controlBudget || w.controlQueued >= w.controlSlots {
		w.err = errEvidenceControlOverflow
		w.mu.Unlock()
		w.store.gap(w.backend, "", "evidence_control_overflow", "writes", 1)
		w.store.fail(errEvidenceControlOverflow)
		return errEvidenceControlOverflow
	}
	w.store.mu.Lock()
	if w.store.rawEvidenceControlPending+uint64(len(data)) > w.globalControlReserve ||
		w.store.stats.RawEvidencePendingBytes+uint64(len(data)) > w.globalDataBudget+w.globalControlReserve {
		w.store.mu.Unlock()
		w.err = errEvidenceControlOverflow
		w.mu.Unlock()
		w.store.gap(w.backend, "", "evidence_control_overflow", "writes", 1)
		w.store.fail(errEvidenceControlOverflow)
		return errEvidenceControlOverflow
	}
	w.store.stats.RawEvidencePendingBytes += uint64(len(data))
	w.store.rawEvidenceControlPending += uint64(len(data))
	if w.store.stats.RawEvidencePendingBytes > w.store.stats.RawEvidenceHighWaterBytes {
		w.store.stats.RawEvidenceHighWaterBytes = w.store.stats.RawEvidencePendingBytes
	}
	w.store.mu.Unlock()
	copied := append([]byte(nil), data...)
	w.controlPending += len(copied)
	w.controlQueued++
	w.queue <- evidenceItem{data: copied, control: true}
	w.mu.Unlock()
	return nil
}

func (w *evidenceWriter) checkAndReserveDataDropLocked(lossData, eventData []byte) (accepted bool, gapDelta uint64, controlErr error) {
	if len(eventData) > evidenceMaxRecordBytes || len(eventData) > w.dataBudget {
		// An oversized event cannot fit even in an empty data queue; drop it as a
		// complete event without wedging subsequent normal-sized events unless the
		// queue is already above its recovery threshold.
		wasShedding := w.shedding
		if w.dataPending > w.dataBudget/2 || w.dataQueued > w.dataSlots/2 {
			w.shedding = true
			w.congested.Store(true)
		}
		return false, w.noteShedLocked(len(eventData), !wasShedding), nil
	}
	w.store.mu.Lock()
	globalPending := w.store.stats.RawEvidencePendingBytes
	globalControlPending := w.store.rawEvidenceControlPending
	globalDataPending := globalPending - globalControlPending
	if w.shedding && !w.dataDrainedLocked(globalDataPending) {
		w.store.mu.Unlock()
		return false, w.noteShedLocked(len(eventData), false), nil
	}
	if w.dataPending+len(eventData) > w.dataBudget || w.dataQueued >= w.dataSlots || globalDataPending+uint64(len(eventData)) > w.globalDataBudget ||
		globalPending+uint64(len(eventData)) > w.globalDataBudget+w.globalControlReserve {
		w.store.mu.Unlock()
		wasShedding := w.shedding
		w.shedding = true
		w.congested.Store(true)
		return false, w.noteShedLocked(len(eventData), !wasShedding), nil
	}
	if len(lossData) > 0 {
		if len(lossData) > evidenceMaxRecordBytes || len(lossData) > w.controlBudget || w.controlPending+len(lossData) > w.controlBudget || w.controlQueued >= w.controlSlots ||
			globalControlPending+uint64(len(lossData)) > w.globalControlReserve ||
			globalPending+uint64(len(lossData)+len(eventData)) > w.globalDataBudget+w.globalControlReserve {
			w.store.mu.Unlock()
			w.err = errEvidenceControlOverflow
			return false, 0, errEvidenceControlOverflow
		}
	}
	w.shedding = false
	w.congested.Store(false)
	w.store.stats.RawEvidencePendingBytes += uint64(len(lossData) + len(eventData))
	w.store.rawEvidenceControlPending += uint64(len(lossData))
	if w.store.stats.RawEvidencePendingBytes > w.store.stats.RawEvidenceHighWaterBytes {
		w.store.stats.RawEvidenceHighWaterBytes = w.store.stats.RawEvidencePendingBytes
	}
	w.store.mu.Unlock()
	if len(lossData) > 0 {
		lossCopy := append([]byte(nil), lossData...)
		w.controlPending += len(lossCopy)
		w.controlQueued++
		w.queue <- evidenceItem{data: lossCopy, control: true}
	}
	eventCopy := append([]byte(nil), eventData...)
	w.dataPending += len(eventCopy)
	w.dataQueued++
	w.queue <- evidenceItem{data: eventCopy, control: false}
	return true, w.takeUnreportedShedLocked(), nil
}

func (w *evidenceWriter) writeData(data []byte) (bool, error) {
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
		reason, err := w.enqueueStrictLocked(data, false)
		w.mu.Unlock()
		if err != nil {
			w.store.gap(w.backend, "", reason, "writes", 1)
			w.store.fail(err)
			return false, err
		}
		return true, nil
	}
	accepted, gapDelta, controlErr := w.checkAndReserveDataDropLocked(nil, data)
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

// writeRecoveryAndData atomically enqueues a preceding loss control record and
// the recovered data event into the same FIFO queue once the data budget can
// accept the event, preventing any post-gap data from overtaking its loss marker.
func (w *evidenceWriter) writeRecoveryAndData(lossData, eventData []byte) (bool, error) {
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
		reason, err := w.enqueueStrictLocked(lossData, true)
		if err == nil {
			reason, err = w.enqueueStrictLocked(eventData, false)
		}
		w.mu.Unlock()
		if err != nil {
			w.store.gap(w.backend, "", reason, "writes", 1)
			w.store.fail(err)
			return false, err
		}
		return true, nil
	}
	accepted, gapDelta, controlErr := w.checkAndReserveDataDropLocked(lossData, eventData)
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
	released := uint64(dataBytes + controlBytes)
	w.store.mu.Lock()
	w.store.rawEvidenceControlPending -= uint64(controlBytes)
	if released >= w.store.stats.RawEvidencePendingBytes {
		w.store.stats.RawEvidencePendingBytes = 0
	} else {
		w.store.stats.RawEvidencePendingBytes -= released
	}
	w.store.mu.Unlock()
	w.mu.Unlock()
}

func (w *evidenceWriter) recordHardFailure(err error) (error, string) {
	classified, reason := classifyEvidenceSinkError(w.backend, err)
	w.mu.Lock()
	if w.err == nil || isEvidenceCongestion(w.err) {
		w.err = classified
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
	writer := bufio.NewWriterSize(w.sink, 64<<10)
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
			if bufferedData+bufferedControl >= 256<<10 || (len(w.queue) == 0 && w.congested.Load()) {
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
				w.err = err
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
