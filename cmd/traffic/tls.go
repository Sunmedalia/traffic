package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/encoding/protowire"
)

// protoFields holds the protobuf fields the eCapture consumer reads. Fixed
// arrays replace the two maps previously allocated per message (twice per
// event), which dominated consumer allocations under load. Field numbers at
// or above protoFieldLimit are validated and skipped.
const protoFieldLimit = 32

type protoFields struct {
	bytes [protoFieldLimit][]byte
	ints  [protoFieldLimit]uint64
}

func (m *protoFields) parse(b []byte) error {
	*m = protoFields{}
	for len(b) > 0 {
		n, t, k := protowire.ConsumeTag(b)
		if k < 0 {
			return fmt.Errorf("invalid protobuf tag")
		}
		b = b[k:]
		switch t {
		case protowire.BytesType:
			x, k := protowire.ConsumeBytes(b)
			if k < 0 {
				return fmt.Errorf("invalid protobuf bytes")
			}
			if n < protoFieldLimit {
				m.bytes[n] = x
			}
			b = b[k:]
		case protowire.VarintType:
			x, k := protowire.ConsumeVarint(b)
			if k < 0 {
				return fmt.Errorf("invalid protobuf integer")
			}
			if n < protoFieldLimit {
				m.ints[n] = x
			}
			b = b[k:]
		default:
			k := protowire.ConsumeFieldValue(n, t, b)
			if k < 0 {
				return fmt.Errorf("invalid protobuf field")
			}
			b = b[k:]
		}
	}
	return nil
}

type probeDrainSummary struct {
	sequence uint64
	dropped  uint64
	perfLost uint64
}

func parseProbeDrainControl(message string) (probeDrainSummary, bool) {
	rest, ok := strings.CutPrefix(message, "traffic-control-v1:drained:")
	if !ok || rest == "" {
		return probeDrainSummary{}, false
	}
	var summary probeDrainSummary
	hasSeq := false
	for _, part := range strings.Split(rest, ",") {
		key, rawVal, found := strings.Cut(part, "=")
		if !found || key == "" || rawVal == "" {
			return probeDrainSummary{}, false
		}
		val, err := strconv.ParseUint(rawVal, 10, 64)
		if err != nil {
			return probeDrainSummary{}, false
		}
		switch key {
		case "seq":
			summary.sequence = val
			hasSeq = true
		case "dropped":
			summary.dropped = val
		case "perf_lost":
			summary.perfLost = val
		}
	}
	return summary, hasSeq
}

type probeProcess struct {
	cmd           *exec.Cmd
	exited        chan struct{}
	waitErr       error
	interruptOnce sync.Once
	reapOnce      sync.Once
	killed        bool
}

func startProbeProcess(cmd *exec.Cmd) (*probeProcess, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &probeProcess{cmd: cmd, exited: make(chan struct{})}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.exited)
	}()
	return p, nil
}

func (p *probeProcess) interrupt() {
	p.interruptOnce.Do(func() {
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Signal(os.Interrupt)
		}
	})
}

func (p *probeProcess) reap(grace time.Duration) (bool, error) {
	p.reapOnce.Do(func() {
		p.interrupt()
		if grace <= 0 {
			select {
			case <-p.exited:
				return
			default:
			}
			if p.cmd.Process != nil {
				p.killed = true
				_ = p.cmd.Process.Kill()
			}
			<-p.exited
			return
		}
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-p.exited:
		case <-timer.C:
			if p.cmd.Process != nil {
				p.killed = true
				_ = p.cmd.Process.Kill()
			}
			<-p.exited
		}
	})
	return !p.killed && p.waitErr == nil, p.waitErr
}

type probeController interface {
	interrupt()
	reap(grace time.Duration) (cleanExit bool, waitErr error)
}

func captureTLS(ctx context.Context, s *Store, p *eventRecorder, bin, lib string, pid, uid int, accepts func(int, string) string, snapshot kernelScopeSnapshot, attached func(), failed ...func(error)) error {
	localDrainTimeout := drainTimeout
	localStopTimeout := stopTimeout
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	addr := listener.Addr().String()
	listener.Close()
	args := []string{"tls", "--libssl", lib, "--mapsize", "1024", "--perf-reorder", "--perf-reorder-lag-ms", "100", "--eventaddr", os.DevNull, "--ecaptureq", "ws://" + addr + "/"}
	if pid > 0 {
		args = append(args, "-p", strconv.Itoa(pid))
	} else {
		args = append(args, "-u", strconv.Itoa(uid))
	}
	for _, name := range []string{"logs", "tls"} {
		if err := os.MkdirAll(filepath.Join(s.dir, name), 0700); err != nil {
			return err
		}
	}
	var scope *kernelScopeFile
	if probeCapability(bin, "feature:pid_scope_v1") {
		scope, e = newKernelScopeFile(filepath.Join(s.dir, "logs"), snapshot, capturePorts)
		if e != nil {
			return e
		}
		defer os.Remove(scope.path)
		args = append(args, "--traffic-scope-file", scope.path)
	}
	if pid == 0 && uid == 0 && scope == nil {
		return fmt.Errorf("grouped root probe requires a verified kernel PID scope")
	}
	log, e := os.OpenFile(filepath.Join(s.dir, "logs", "tls.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer log.Close()

	probeKey := fmt.Sprintf("ecapture/%s/%d/%d", lib, uid, pid)
	logSink := &probeLog{file: log, store: s}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = logSink
	releaseParentThread := bindProbeParent(cmd)
	defer releaseParentThread()

	probeProc, err := startProbeProcess(cmd)
	if err != nil {
		return err
	}

	var stopAt atomic.Int64
	var drainTimedOut atomic.Bool
	reapBudget := func() time.Duration {
		if ns := stopAt.Load(); ns > 0 {
			remaining := localStopTimeout - time.Since(time.Unix(0, ns))
			if remaining <= 0 {
				return 0
			}
			if drainTimedOut.Load() {
				return min(50*time.Millisecond, max(10*time.Millisecond, remaining/4))
			}
			reserve := min(200*time.Millisecond, remaining/4)
			return min(5*time.Second, max(25*time.Millisecond, remaining-reserve))
		}
		return min(2*time.Second, localDrainTimeout)
	}
	exitRecorded := false
	recordExit := func(exit session.ProbeExit) {
		exitRecorded = true
		s.recordProbeExit(probeKey, exit)
	}
	defer func() {
		cleanExit, _ := probeProc.reap(reapBudget())
		if !exitRecorded {
			recordExit(session.ProbeExit{
				DataDrained:       false,
				TransportDetached: cleanExit,
				RuntimeState:      "probe exited before drain confirmation",
			})
		}
	}()

	var ws *websocket.Conn
	dialHandshake := min(time.Second, localDrainTimeout)
	for i := 0; i < 60; i++ {
		ws, _, e = (&websocket.Dialer{HandshakeTimeout: dialHandshake}).DialContext(ctx, "ws://"+addr+"/", http.Header{"Origin": []string{"http://" + addr}})
		if e == nil {
			break
		}
		select {
		case <-probeProc.exited:
			recordExit(session.ProbeExit{
				DataDrained:       false,
				TransportDetached: true,
				RuntimeState:      "probe exited before transport connected",
			})
			if probeProc.waitErr != nil {
				return fmt.Errorf("TLS probe exited before transport connected: %w", probeProc.waitErr)
			}
			return fmt.Errorf("TLS probe exited before transport connected")
		case <-ctx.Done():
			stopAt.CompareAndSwap(0, time.Now().UnixNano())
			cleanExit, _ := probeProc.reap(reapBudget())
			s.gap("ecapture", lib, "drain_unconfirmed", "shutdowns", 1)
			recordExit(session.ProbeExit{
				DataDrained:       false,
				TransportDetached: cleanExit,
				RuntimeState:      "probe stopped before transport connected",
			})
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
	if e != nil {
		return e
	}
	defer ws.Close()
	if scope != nil {
		stopScope := scope.watch(ctx, func(err error) {
			s.gap("ecapture", lib, "scope_update_failed", "updates", 1)
			s.problem(err)
			ws.Close()
		})
		defer stopScope()
	}
	ws.SetReadLimit(2 << 20)
	return consumeTLSProbe(ctx, s, p, lib, probeKey, ws, probeProc, logSink, scope != nil, localDrainTimeout, &stopAt, &drainTimedOut, reapBudget, recordExit, accepts, attached, failed...)
}

func consumeTLSProbe(
	ctx context.Context,
	s *Store,
	p *eventRecorder,
	lib string,
	probeKey string,
	reader probeMessageReader,
	proc probeController,
	logSink *probeLog,
	scoped bool,
	localDrainTimeout time.Duration,
	stopAt *atomic.Int64,
	drainTimedOut *atomic.Bool,
	reapBudget func() time.Duration,
	recordExit func(session.ProbeExit),
	accepts func(int, string) string,
	attached func(),
	failed ...func(error),
) error {
	transport := startProbeTransport(reader, func(err error) {
		if ctx.Err() == nil {
			s.mu.Lock()
			s.stats.ProbeFailures++
			s.mu.Unlock()
			for _, callback := range failed {
				callback(err)
			}
		}
	})
	defer transport.close()
	epoch := serial.Add(1)
	stopMetrics := s.observeProbeTransport(probeKey, epoch, transport)
	defer stopMetrics()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			stopAt.CompareAndSwap(0, time.Now().UnixNano())
			proc.interrupt()
			timer := time.NewTimer(localDrainTimeout)
			defer timer.Stop()
			select {
			case <-timer.C:
				drainTimedOut.Store(true)
				_ = reader.Close()
			case <-watchDone:
			}
		case <-watchDone:
		}
	}()
	ready := false
	markReady := func() {
		if ready {
			return
		}
		ready = true
		attached()
	}
	source := fmt.Sprintf("ecapture-%d", epoch)
	endReason := "probe_stopped"
	defer func() {
		if err := p.boundary(source, session.RawEvent{Type: "end", Reason: endReason}); err != nil {
			s.fail(err)
		}
	}()
	var sequence probeSequence
	var drainSummary *probeDrainSummary
	sawEventAfterDrain := false
	sawUnsequencedData := false
	identityWarning, portWarning := false, false
	var outerMessage, eventMessage protoFields
	shedLoss := func(shed uint64) error {
		if shed == 0 {
			return nil
		}
		s.gap("ecapture", lib, "receive_queue_shed", "messages", shed)
		return p.boundary(source, session.RawEvent{Type: "loss", Reason: "receive_queue_shed", Unit: "messages", Count: shed})
	}
	var pendingShed uint64
	for {
		b, shed, e := transport.next()
		if err := shedLoss(shed); err != nil {
			return err
		}
		pendingShed += shed
		if drainSummary != nil && shed > 0 {
			sawEventAfterDrain = true
		}
		if e != nil {
			if ctx.Err() != nil {
				cleanExit, waitErr := proc.reap(reapBudget())
				if drainSummary == nil {
					if drainTimedOut.Load() {
						s.gap("ecapture", lib, "drain_timeout", "shutdowns", 1)
					}
					s.gap("ecapture", lib, "drain_unconfirmed", "shutdowns", 1)
					state := "probe process stopped; transport drain not confirmed"
					if drainTimedOut.Load() {
						state = "probe drain timed out before final confirmation"
					}
					recordExit(session.ProbeExit{
						DataDrained:       false,
						TransportDetached: cleanExit,
						RuntimeState:      state,
					})
					return nil
				}
				if logSink != nil {
					logSink.reconcilePerfLost(drainSummary.perfLost)
				}
				if !sawUnsequencedData && drainSummary.sequence > sequence.last {
					tailMissing := drainSummary.sequence - sequence.last
					if pendingShed > 0 {
						tailMissing -= min(tailMissing, pendingShed)
					}
					pendingShed = 0
					if tailMissing > 0 {
						s.gap("ecapture", lib, "sequence_gap", "published_events", tailMissing)
						if err := p.boundary(source, session.RawEvent{Type: "loss", Reason: "sequence_gap", Unit: "published_events", Count: tailMissing}); err != nil {
							return err
						}
					}
				}
				seqMatches := !sawUnsequencedData && drainSummary.sequence == sequence.last && !sawEventAfterDrain
				if !seqMatches {
					s.gap("ecapture", lib, "drain_sequence_mismatch", "shutdowns", 1)
				}
				confirmed := seqMatches && pendingShed == 0 && !drainTimedOut.Load() && cleanExit && waitErr == nil
				if !confirmed && seqMatches {
					if drainTimedOut.Load() {
						s.gap("ecapture", lib, "drain_timeout", "shutdowns", 1)
					}
					s.gap("ecapture", lib, "drain_unconfirmed", "shutdowns", 1)
				}
				state := "probe process stopped; final event sequence confirmed"
				if !confirmed {
					state = "probe process stopped; final boundary mismatch or incomplete exit"
				}
				recordExit(session.ProbeExit{
					DataDrained:       confirmed,
					TransportDetached: cleanExit,
					RuntimeState:      state,
				})
				return nil
			}
			endReason = "transport_interrupted"
			s.gap("ecapture", lib, "transport_interrupted", "transports", 1)
			cleanExit, _ := proc.reap(reapBudget())
			recordExit(session.ProbeExit{
				DataDrained:       false,
				TransportDetached: cleanExit,
				RuntimeState:      "probe transport interrupted",
			})
			return e
		}
		if e := outerMessage.parse(b); e != nil {
			return e
		}
		outer, outerNumbers := &outerMessage.bytes, &outerMessage.ints
		if outerNumbers[1] == 1 {
			controlMsg := string(outer[4])
			if controlMsg == "traffic-control-v1:ready" {
				markReady()
				continue
			}
			if controlMsg == "traffic-control-v1:scope-error" {
				s.gap("ecapture", lib, "kernel_scope_update_failed", "updates", 1)
				return fmt.Errorf("kernel PID scope update failed; probe cleared its PID allowlist")
			}
			if summary, ok := parseProbeDrainControl(controlMsg); ok {
				if drainSummary != nil {
					sawEventAfterDrain = true
				} else {
					drainSummary = &summary
				}
				continue
			}
		}
		if outer[2] == nil {
			continue
		}
		if drainSummary != nil {
			sawEventAfterDrain = true
		}
		if e := eventMessage.parse(outer[2]); e != nil {
			return e
		}
		fields, nums := &eventMessage.bytes, &eventMessage.ints
		if nums[17] == 0 {
			sawUnsequencedData = true
		}
		missing, reset := sequence.observe(nums[17])
		// Messages shed locally were already reported above; only report the
		// remainder as probe-side sequence loss so one gap is not counted twice.
		if pendingShed > 0 && !reset {
			missing -= min(missing, pendingShed)
		}
		pendingShed = 0
		if missing > 0 || reset {
			if missing > 0 {
				s.gap("ecapture", lib, "sequence_gap", "published_events", missing)
			}
			if reset {
				s.gap("ecapture", lib, "sequence_reset_or_reorder", "transitions", 1)
			}
			boundary := session.RawEvent{Type: "loss", Reason: "sequence_gap", Unit: "published_events", Count: missing}
			if reset {
				boundary.Reason, boundary.Unit, boundary.Count = "sequence_reset_or_reorder", "transitions", 1
			}
			if err := p.boundary(source, boundary); err != nil {
				return err
			}
		}
		if nums[6] != 0 && !capturePorts[int(nums[6])] {
			continue
		}
		reportedIdentity := ""
		if scoped {
			reportedIdentity = processStartIdentity(string(fields[16]), int(nums[7]))
		}
		identity := accepts(int(nums[7]), reportedIdentity)
		if identity == "" {
			continue
		}
		// A valid scoped event also proves readiness for older probes without
		// the explicit control record. Opening their socket alone does not.
		markReady()
		if nums[6] == 0 {
			s.mu.Lock()
			s.stats.TLSDropped++
			s.mu.Unlock()
			if !portWarning {
				s.problem(fmt.Errorf("TLS event lacks socket endpoints; cannot apply port filter"))
				portWarning = true
			}
			continue
		}
		payload := fields[11]

		key := string(fields[2])
		if len(fields[3]) > 0 && len(fields[5]) > 0 {
			key = fmt.Sprintf("%d/%s:%d|%s:%d", nums[7], fields[3], nums[4], fields[5], nums[6])
		}
		if len(fields[16]) > 0 {
			key = string(fields[16])
		}
		if strings.HasPrefix(key, "unknown_") {
			s.mu.Lock()
			s.stats.TLSDropped++
			s.mu.Unlock()
			if !identityWarning {
				s.problem(fmt.Errorf("TLS probe lacks connection identity; rebuild the bundled eCapture probe"))
				identityWarning = true
			}
			continue
		}
		key = fmt.Sprintf("probe-%d/%s", epoch, key)
		client := "unknown"
		if len(fields[3]) > 0 {
			client = net.JoinHostPort(string(fields[3]), strconv.Itoa(int(nums[4])))
		}
		target := p.target(int(nums[7]), identity)
		kind := "data"
		if len(payload) == 0 {
			kind = "close"
		}
		if err := p.record(source+"/"+identity, "ecapture", target, session.RawEvent{Type: kind, Connection: key, Direction: string(fields[14]), Data: payload, Local: net.JoinHostPort(string(fields[5]), strconv.Itoa(int(nums[6]))), Client: client}); err != nil {
			return err
		}
	}
}

type probeLog struct {
	file          *os.File
	store         *Store
	rawLost       uint64
	accountedLost uint64
}

var ansi = regexp.MustCompile(` \[[0-9;]*m`)
var lost = regexp.MustCompile(`lost_samples=([0-9]+)`)

func (l *probeLog) Write(b []byte) (int, error) {
	plain := ansi.ReplaceAll(b, nil)
	var batch uint64
	for _, m := range lost.FindAllSubmatch(plain, -1) {
		n, _ := strconv.ParseUint(string(m[1]), 10, 64)
		batch += n
	}
	if batch > 0 {
		l.store.mu.Lock()
		l.rawLost += batch
		if l.rawLost > l.accountedLost {
			delta := l.rawLost - l.accountedLost
			l.accountedLost = l.rawLost
			l.store.stats.TLSDropped += delta
		}
		l.store.mu.Unlock()
	}
	return l.file.Write(b)
}

func (l *probeLog) reconcilePerfLost(total uint64) {
	if total == 0 {
		return
	}
	l.store.mu.Lock()
	if total > l.accountedLost {
		delta := total - l.accountedLost
		l.accountedLost = total
		l.store.stats.TLSDropped += delta
	}
	l.store.mu.Unlock()
}
