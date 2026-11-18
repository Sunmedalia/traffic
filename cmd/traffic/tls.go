package main

import (
	"context"
	"fmt"
	"github.com/Sunmedalia/traffic/internal/session"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

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
func captureTLS(ctx context.Context, s *Store, p *eventRecorder, bin, lib string, pid, uid int, accepts func(int, string) string, snapshot kernelScopeSnapshot, attached func(), failed ...func(error)) error {
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
	cmd := exec.Command(bin, args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	cmd.Stderr = &probeLog{file: log, store: s}
	releaseParentThread := bindProbeParent(cmd)
	defer releaseParentThread()
	if e = cmd.Start(); e != nil {
		return e
	}
	go io.Copy(io.Discard, pipe)
	defer func() {
		cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}()
	var ws *websocket.Conn
	for i := 0; i < 60; i++ {
		ws, _, e = (&websocket.Dialer{HandshakeTimeout: time.Second}).DialContext(ctx, "ws://"+addr+"/", http.Header{"Origin": []string{"http://" + addr}})
		if e == nil {
			break
		}
		select {
		case <-ctx.Done():
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
	transport := startProbeTransport(ws, func(err error) {
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
	stopMetrics := s.observeProbeTransport(fmt.Sprintf("ecapture/%s/%d/%d", lib, uid, pid), epoch, transport)
	defer stopMetrics()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			ws.Close()
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
	defer func() {
		if err := p.boundary(source, session.RawEvent{Type: "end", Reason: "probe_stopped"}); err != nil {
			s.fail(err)
		}
	}()
	var sequence probeSequence
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
		if e != nil {
			if ctx.Err() != nil {
				s.gap("ecapture", lib, "drain_unconfirmed", "shutdowns", 1)
				s.recordProbeExit("ecapture/"+lib, session.ProbeExit{RuntimeState: "probe process stopped; transport drain not confirmed"})
				return nil
			}
			s.gap("ecapture", lib, "transport_interrupted", "transports", 1)
			return e
		}
		if e := outerMessage.parse(b); e != nil {
			return e
		}
		outer, outerNumbers := &outerMessage.bytes, &outerMessage.ints
		if outerNumbers[1] == 1 && string(outer[4]) == "traffic-control-v1:ready" {
			markReady()
			continue
		}
		if outerNumbers[1] == 1 && string(outer[4]) == "traffic-control-v1:scope-error" {
			s.gap("ecapture", lib, "kernel_scope_update_failed", "updates", 1)
			return fmt.Errorf("kernel PID scope update failed; probe cleared its PID allowlist")
		}
		if outer[2] == nil {
			continue
		}
		if e := eventMessage.parse(outer[2]); e != nil {
			return e
		}
		fields, nums := &eventMessage.bytes, &eventMessage.ints
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
		if scope != nil {
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
	file  *os.File
	store *Store
}

var ansi = regexp.MustCompile(`\[[0-9;]*m`)
var lost = regexp.MustCompile(`lost_samples=([0-9]+)`)

func (l *probeLog) Write(b []byte) (int, error) {
	plain := ansi.ReplaceAll(b, nil)
	for _, m := range lost.FindAllSubmatch(plain, -1) {
		n, _ := strconv.ParseUint(string(m[1]), 10, 64)
		l.store.mu.Lock()
		l.store.stats.TLSDropped += n
		l.store.mu.Unlock()
	}
	return l.file.Write(b)
}
