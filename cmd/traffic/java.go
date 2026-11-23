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

func captureJava(ctx context.Context, s *Store, p *eventRecorder, t session.Target, jar, helper string, attached func()) error {
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
	helper, helperArgs, err := javaAttachCommand("/proc", t.PID, helper, jar)
	if err != nil {
		return err
	}
	command := exec.CommandContext(attachCtx, helper, append(helperArgs, "traffic.agent.Attach", strconv.Itoa(t.PID), jar, config.Name())...)
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
	source := fmt.Sprintf("java-%d/%s", serial.Add(1), t.ID)
	defer func() {
		if err := p.record(source, "java-agent", t, session.RawEvent{Type: "end"}); err != nil {
			s.fail(err)
		}
	}()
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
			missing := event.Dropped - lastDropped
			s.gap("java-agent", t.ID, "probe_queue_loss", "events", missing)
			lastDropped = event.Dropped
			if err := p.record(source, "java-agent", t, session.RawEvent{Type: "loss", Reason: "probe_queue_loss", Count: missing}); err != nil {
				return err
			}
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
				reason, unit, count := sequenceDiscontinuity(lastSequence, event.Sequence)
				s.gap("java-agent", t.ID, reason, unit, count)
				if err := p.record(source, "java-agent", t, session.RawEvent{Type: "loss", Reason: reason, Unit: unit, Count: count}); err != nil {
					return err
				}
			}
			lastSequence = event.Sequence
		}
		if event.Type != "heartbeat" && capturePorts[event.Port] {
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
			}
			if err := p.record(source, "java-agent", t, session.RawEvent{Type: "data", Connection: key, Direction: direction, Data: event.Payload, Client: event.Client, Local: event.Local, Incomplete: event.Incomplete}); err != nil {
				return err
			}

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

// javaAttachCommand returns the attach helper and its JVM options. JDK 9+ exposes the
// attach API as the jdk.attach module, while JDK 8 ships it in the JDK's lib/tools.jar,
// which must be put on the class path; a JDK 8 JRE has neither.
func javaAttachCommand(proc string, pid int, helper, jar string) (string, []string, error) {
	// Paths read from /proc/PID/exe are inside the target's mount namespace.
	root := "/"
	resolved := helper
	if helper == "" {
		helper = filepath.Join(proc, strconv.Itoa(pid), "exe")
		root = filepath.Join(proc, strconv.Itoa(pid), "root")
		link, err := os.Readlink(helper)
		if err != nil {
			return "", nil, fmt.Errorf("Java helper: %w", err)
		}
		resolved = strings.TrimSuffix(link, " (deleted)")
	} else {
		var err error
		helper, err = exec.LookPath(helper)
		if err != nil {
			return "", nil, fmt.Errorf("Java helper: %w", err)
		}
		resolved, err = filepath.EvalSymlinks(helper)
		if err != nil {
			return "", nil, fmt.Errorf("Java helper: %w", err)
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return "", nil, fmt.Errorf("Java helper: %w", err)
		}
	}
	home := filepath.Dir(filepath.Dir(resolved))
	if _, err := os.Stat(filepath.Join(root, home, "lib", "modules")); err == nil {
		return helper, []string{"--add-modules", "jdk.attach", "-cp", jar}, nil
	}
	// JDK 8 runs either bin/java or jre/bin/java; tools.jar is in the JDK's lib.
	for _, candidate := range []string{filepath.Join(home, "lib", "tools.jar"), filepath.Join(filepath.Dir(home), "lib", "tools.jar")} {
		if readableFile(filepath.Join(root, candidate)) {
			return helper, []string{"-cp", jar + string(os.PathListSeparator) + filepath.Join(root, candidate)}, nil
		}
	}
	return "", nil, fmt.Errorf("Java helper %s has no attach API (JDK 8 needs lib/tools.jar from a JDK, not a JRE); use --java-helper with a JDK", resolved)
}
