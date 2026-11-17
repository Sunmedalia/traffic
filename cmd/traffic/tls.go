package main

import (
	"context"
	"encoding/json"
	"errors"
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

func protoFields(b []byte) (map[int][]byte, map[int]uint64, error) {
	s := map[int][]byte{}
	v := map[int]uint64{}
	for len(b) > 0 {
		n, t, k := protowire.ConsumeTag(b)
		if k < 0 {
			return nil, nil, fmt.Errorf("invalid protobuf tag")
		}
		b = b[k:]
		switch t {
		case protowire.BytesType:
			x, k := protowire.ConsumeBytes(b)
			if k < 0 {
				return nil, nil, fmt.Errorf("invalid protobuf bytes")
			}
			s[int(n)] = x
			b = b[k:]
		case protowire.VarintType:
			x, k := protowire.ConsumeVarint(b)
			if k < 0 {
				return nil, nil, fmt.Errorf("invalid protobuf integer")
			}
			v[int(n)] = x
			b = b[k:]
		default:
			k := protowire.ConsumeFieldValue(n, t, b)
			if k < 0 {
				return nil, nil, fmt.Errorf("invalid protobuf field")
			}
			b = b[k:]
		}
	}
	return s, v, nil
}
func captureTLS(ctx context.Context, s *Store, p *HTTPProcessor, bin, lib string, pid, uid int, accepts func(int, string) string, snapshot kernelScopeSnapshot, attached func(), failed ...func(error)) error {
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
	events, err := os.OpenFile(filepath.Join(s.dir, "tls", "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	evidence := newEvidenceWriter(s, events, "ecapture")
	defer evidence.Close()
	enc := json.NewEncoder(evidence)
	var sequence probeSequence
	transportUncertain := false
	identityWarning := false
	portWarning := false
	frames := &Frames{}
	stopExpiry := frames.startExpiry(ctx, p)
	defer func() {
		stopExpiry()
		p.invalidatePrefix(fmt.Sprintf("tls:probe-%d/", epoch), "probe_connection_closed")
	}()
	for {
		b, e := transport.next()
		if e != nil {
			if ctx.Err() != nil {
				s.gap("ecapture", lib, "drain_unconfirmed", "shutdowns", 1)
				s.recordProbeExit("ecapture/"+lib, session.ProbeExit{RuntimeState: "probe process stopped; transport drain not confirmed"})
				return nil
			}
			reason := "transport_interrupted"
			if errors.Is(e, errProbeTransportBackpressure) {
				reason = "receive_queue_overflow"
			}
			s.gap("ecapture", lib, reason, "transports", 1)
			return e
		}
		outer, outerNumbers, e := protoFields(b)
		if e != nil {
			return e
		}
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
		fields, nums, e := protoFields(outer[2])
		if e != nil {
			return e
		}
		missing, reset := sequence.observe(nums[17])
		if missing > 0 || reset {
			transportUncertain = true
			if missing > 0 {
				s.gap("ecapture", lib, "sequence_gap", "published_events", missing)
			}
			if reset {
				s.gap("ecapture", lib, "sequence_reset_or_reorder", "transitions", 1)
			}
			frames.expire(time.Now(), true, p, "")
			p.invalidatePrefix(fmt.Sprintf("tls:probe-%d/", epoch), "probe_sequence_gap")
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
		if err := enc.Encode(map[string]any{"fields": fields, "numbers": nums}); err != nil {
			s.fail(fmt.Errorf("save TLS evidence: %w", err))
			return err
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
		if len(payload) == 0 {
			if string(fields[14]) == "read" {
				frames.expire(time.Now(), true, p, key)
			}
			continue
		}
		p.mu.Lock()
		queue := p.pending["tls:"+key]
		head := len(queue) > 0 && queue[0].Method == "HEAD"
		p.mu.Unlock()
		frames.ingest(key+string(fields[14]), payload, frameContext{incomplete: transportUncertain, targetID: identity, connection: key, client: client, pid: int(nums[7]), local: net.JoinHostPort(string(fields[5]), strconv.Itoa(int(nums[6])))}, head, p)
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
