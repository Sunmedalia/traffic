//go:build !windows

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

func captureJava(ctx context.Context, s *Store, p *HTTPProcessor, t session.Target, jar, helper string, attached func()) error {
	jar, err := filepath.Abs(jar)
	if err != nil {
		return err
	}
	if _, err = os.Stat(jar); err != nil {
		return err
	}
	runtimeDir, err := os.MkdirTemp("", "traffic-java-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(runtimeDir)
	if err = os.Chown(runtimeDir, t.UID, -1); err != nil {
		return err
	}
	input, err := os.Open(jar)
	if err != nil {
		return err
	}
	defer input.Close()
	staged := filepath.Join(runtimeDir, "agent.jar")
	output, err := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Chown(staged, t.UID, -1); err != nil {
		return err
	}
	jar = staged
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return err
	}
	token := hex.EncodeToString(secret)
	config, err := os.CreateTemp(runtimeDir, "config-*.properties")
	if err != nil {
		return err
	}
	defer os.Remove(config.Name())
	if err = os.Chown(config.Name(), t.UID, -1); err != nil {
		config.Close()
		return err
	}
	var ports []string
	for port := range capturePorts {
		ports = append(ports, strconv.Itoa(port))
	}
	sort.Strings(ports)
	_, err = fmt.Fprintf(config, "port=%d\ntoken=%s\nprotocol=traffic-java-v2\nports=%s\n", listener.Addr().(*net.TCPAddr).Port, token, strings.Join(ports, ","))
	config.Close()
	if err != nil {
		return err
	}
	attachCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if helper == "" {
		helper = fmt.Sprintf("/proc/%d/exe", t.PID)
	}
	command := exec.CommandContext(attachCtx, helper, "--add-modules", "jdk.attach", "-cp", jar, "traffic.agent.Attach", strconv.Itoa(t.PID), jar, config.Name())
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(t.UID), Gid: uint32(t.GID)}}
	result := make(chan error, 1)
	go func() {
		output, err := command.CombinedOutput()
		if err != nil {
			err = fmt.Errorf("Java attach: %w: %.1000s", err, output)
		}
		result <- err
		if err != nil {
			listener.Close()
		}
	}()
	conn, err := listener.Accept()
	if err != nil {
		select {
		case err = <-result:
			return err
		default:
			return err
		}
	}
	defer conn.Close()
	var stopping atomic.Bool
	go func() {
		select {
		case <-ctx.Done():
			stopping.Store(true)
			conn.SetDeadline(time.Now().Add(drainTimeout))
		case <-done:
		}
	}()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 128<<10)
	if !scanner.Scan() || (scanner.Text() != token+"|traffic-java-v1" && scanner.Text() != token+"|traffic-java-v2") {
		return fmt.Errorf("Java probe authentication or protocol version mismatch")
	}
	if _, err = conn.Write([]byte{1}); err != nil {
		return err
	}
	if err = <-result; err != nil {
		return err
	}
	conn.SetDeadline(time.Time{})
	if ctx.Err() != nil {
		conn.SetDeadline(time.Now().Add(drainTimeout))
	}
	attached()
	s.mu.Lock()
	s.stats.TLS = "attached"
	s.mu.Unlock()
	dir := filepath.Join(s.dir, "tls")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	evidence, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("java-%d.jsonl", t.PID)), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	raw := newEvidenceWriter(s, evidence, "java-agent")
	defer raw.Close()
	frames := &Frames{}
	stop := frames.startExpiry(ctx, p)
	defer stop()
	var lastSequence, lastDropped uint64
	for scanner.Scan() {
		var event struct {
			Sequence   uint64
			Dropped    uint64
			Local      string
			Port       int
			Type       string
			Connection string
			Client     string
			Read       bool
			Incomplete bool
			Payload    []byte
		}
		if err = json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return err
		}
		if event.Dropped > lastDropped {
			s.gap("java-agent", t.ID, "probe_queue_loss", "events", event.Dropped-lastDropped)
			lastDropped = event.Dropped
			frames.expire(time.Now(), true, p, "")
			p.invalidatePrefix("tls:java:"+t.ID+":", "probe_queue_loss")
		}
		if event.Type == "drained" {
			confirmed := event.Sequence == lastSequence
			if !confirmed {
				s.gap("java-agent", t.ID, "drain_sequence_mismatch", "shutdowns", 1)
			}
			s.recordProbeExit(t.ID, session.ProbeExit{DataDrained: confirmed, RuntimeState: "agent classes may remain loaded"})
			return nil
		}
		if event.Sequence > 0 {
			if lastSequence > 0 && event.Sequence != lastSequence+1 {
				s.gap("java-agent", t.ID, "transport_sequence_gap", "events", 1)
				p.invalidatePrefix("tls:java:"+t.ID+":", "transport_sequence_gap")
			}
			lastSequence = event.Sequence
		}
		if event.Type != "heartbeat" && capturePorts[event.Port] {
			if _, err = raw.Write(append(append([]byte{}, scanner.Bytes()...), '\n')); err != nil {
				return err
			}
			key := "java:" + t.ID + ":" + event.Connection
			direction := "write"
			if event.Read {
				direction = "read"
			}
			if event.Incomplete {
				if event.Sequence == 0 && event.Dropped == 0 {
					s.mu.Lock()
					s.stats.TLSDropped++
					s.mu.Unlock()
					s.gap("java-agent", key, "legacy_gap_marker", "events", 1)
				}
				frames.expire(time.Now(), true, p, key)
			}
			p.mu.Lock()
			q := p.pending["tls:"+key]
			head := len(q) > 0 && q[0].Method == "HEAD"
			p.mu.Unlock()
			frames.ingest(key+direction, event.Payload, frameContext{connection: key, client: event.Client, pid: t.PID, incomplete: event.Incomplete, local: event.Local}, head, p)
		}
		control := byte(1)
		if stopping.Load() {
			control = 2
		}
		if _, err = conn.Write([]byte{control}); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		s.gap("java-agent", t.ID, "drain_unconfirmed", "shutdowns", 1)
		return nil
	}
	if scanner.Err() != nil {
		return scanner.Err()
	}
	return fmt.Errorf("Java probe disconnected")
}
