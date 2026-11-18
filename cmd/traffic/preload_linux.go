package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Sunmedalia/traffic/internal/session"
)

// The socket is private to the collector UID by default. An explicit UID
// allowlist opens it to the service account (for example nginx workers running
// as www-data) and keeps kernel credentials as the first identity check.
func openPreloadSocket(path string, allowedUIDs []uint32) (*net.UnixConn, error) {
	if len([]byte(path)) >= 108 {
		return nil, fmt.Errorf("preload socket path must be shorter than 108 bytes")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("--openssl-preload-socket must be absolute")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, fmt.Errorf("preload socket path must not exist: %s", path)
	}
	directory := filepath.Dir(path)
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		if err := os.MkdirAll(directory, 0755); err != nil {
			return nil, fmt.Errorf("preload socket directory: %w", err)
		}
		// The collector runs with a private umask; the socket parent must stay
		// traversable for the allowlisted service account.
		if err := os.Chmod(directory, 0755); err != nil {
			return nil, fmt.Errorf("preload socket directory mode: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("preload socket directory: %w", err)
	}
	// Existing directory permissions belong to the operator. The UID opt-in
	// grants access to the socket; it must not expose a private parent directory.
	connection, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	cleanup := func(err error) (*net.UnixConn, error) { connection.Close(); os.Remove(path); return nil, err }
	mode := os.FileMode(0600)
	if len(allowedUIDs) > 0 {
		mode = 0660
	}
	if err := os.Chmod(path, mode); err != nil {
		return cleanup(err)
	}
	if len(allowedUIDs) > 0 {
		account, err := user.LookupId(strconv.FormatUint(uint64(allowedUIDs[0]), 10))
		if err != nil {
			return cleanup(fmt.Errorf("preload sender UID %d: %w", allowedUIDs[0], err))
		}
		group, err := strconv.Atoi(account.Gid)
		if err != nil {
			return cleanup(fmt.Errorf("preload sender group for UID %d: %w", allowedUIDs[0], err))
		}
		if err := os.Chown(path, -1, group); err != nil {
			return cleanup(err)
		}
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return cleanup(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil {
		return cleanup(err)
	}
	if optionErr != nil {
		return cleanup(optionErr)
	}
	if err := connection.SetReadBuffer(4 << 20); err != nil {
		return cleanup(err)
	}
	return connection, nil
}

func preloadUIDAllowed(uid uint32, allowedUIDs []uint32) bool {
	if uid == uint32(os.Geteuid()) {
		return true
	}
	for _, allowed := range allowedUIDs {
		if uid == allowed {
			return true
		}
	}
	return false
}

// stopPreloadAccepting unlinks the socket path and shuts down receive-side
// intake (SHUT_RD) so new and already-connected senders immediately receive
// ENOENT/EPIPE, while datagrams already queued in SO_RCVBUF remain readable.
func stopPreloadAccepting(connection *net.UnixConn, path string) error {
	var removeErr error
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		removeErr = err
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return errors.Join(removeErr, err)
	}
	var shutdownErr error
	controlErr := raw.Control(func(fd uintptr) {
		if err := unix.Shutdown(int(fd), unix.SHUT_RD); err != nil && !errors.Is(err, unix.ENOTCONN) {
			shutdownErr = err
		}
	})
	return errors.Join(removeErr, controlErr, shutdownErr)
}

func recvPreloadNonblocking(raw syscall.RawConn, buffer, ancillary []byte) (n, oobn, flags int, empty bool, err error) {
	var recvErr error
	ctlErr := raw.Control(func(fd uintptr) {
		n, oobn, flags, _, recvErr = unix.Recvmsg(int(fd), buffer, ancillary, unix.MSG_DONTWAIT)
	})
	if ctlErr != nil {
		return 0, 0, 0, false, ctlErr
	}
	if errors.Is(recvErr, unix.EAGAIN) || errors.Is(recvErr, unix.EWOULDBLOCK) {
		return 0, 0, 0, true, nil
	}
	if recvErr != nil {
		return 0, 0, 0, false, recvErr
	}
	if n == 0 && oobn == 0 {
		return 0, 0, 0, true, nil
	}
	return n, oobn, flags, false, nil
}

func capturePreload(ctx context.Context, s *Store, p *eventRecorder, path string, allowedUIDs []uint32) error {
	connection, err := openPreloadSocket(path, allowedUIDs)
	if err != nil {
		return err
	}
	defer connection.Close()
	defer os.Remove(path)
	rawConn, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	type rawTarget struct {
		pid          int
		target       session.Target
		lastSequence uint64
	}
	assemblers := map[string]*rawTarget{}
	endReason := "probe_stopped"
	exitRecorded := false
	defer func() {
		ids := make([]string, 0, len(assemblers))
		for id := range assemblers {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			a := assemblers[id]
			if err := p.record("preload/"+id, "openssl-preload", a.target, session.RawEvent{Type: "end", Reason: endReason}); err != nil {
				s.fail(err)
			}
		}
		if !exitRecorded {
			s.recordProbeExit("openssl-preload", session.ProbeExit{
				DataDrained:  false,
				RuntimeState: "preload collector exited before completing socket drain",
			})
		}
	}()
	stopDone := make(chan struct{})
	defer close(stopDone)
	var stopAcceptOnce sync.Once
	var stopAcceptErr error
	stopAccepting := func() {
		stopAcceptOnce.Do(func() {
			stopAcceptErr = stopPreloadAccepting(connection, path)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			stopAccepting()
		case <-stopDone:
		}
	}()
	buffer := make([]byte, 32768)
	ancillary := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	s.mu.Lock()
	s.stats.TLS = "listening-preload"
	s.mu.Unlock()
	s.report()
	localDrainTimeout := drainTimeout
	draining := false
	var drainDeadline time.Time
	socketDrained := false
	drainTimedOut := false
	for {
		if !draining && ctx.Err() != nil {
			draining = true
			stopAccepting()
			drainDeadline = time.Now().Add(localDrainTimeout)
		}
		var (
			n, oobn, flags int
			empty          bool
		)
		if draining {
			if !time.Now().Before(drainDeadline) {
				drainTimedOut = true
				break
			}
			n, oobn, flags, empty, err = recvPreloadNonblocking(rawConn, buffer, ancillary)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, unix.EBADF) {
					break
				}
				exitRecorded = true
				s.recordProbeExit("openssl-preload", session.ProbeExit{
					DataDrained:  false,
					RuntimeState: "preload socket read failed during drain",
				})
				return err
			}
			if empty {
				socketDrained = true
				break
			}
		} else {
			connection.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, oobn, flags, _, err = connection.ReadMsgUnix(buffer, ancillary)
			if err != nil {
				if ctx.Err() != nil {
					draining = true
					stopAccepting()
					drainDeadline = time.Now().Add(localDrainTimeout)
					continue
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					continue
				}
				endReason = "transport_interrupted"
				s.gap("openssl-preload", path, "transport_interrupted", "transports", 1)
				exitRecorded = true
				s.recordProbeExit("openssl-preload", session.ProbeExit{
					DataDrained:  false,
					RuntimeState: "preload socket interrupted",
				})
				return err
			}
			if n == 0 && oobn == 0 {
				continue
			}
		}
		messages, err := unix.ParseSocketControlMessage(ancillary[:oobn])
		if err != nil {
			continue
		}
		var credentials *unix.Ucred
		for _, message := range messages {
			if credential, e := unix.ParseUnixCredentials(&message); e == nil {
				credentials = credential
			}
		}
		if credentials == nil || !preloadUIDAllowed(credentials.Uid, allowedUIDs) {
			continue
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			s.mu.Lock()
			s.stats.TLSDropped++
			s.mu.Unlock()
			continue
		}
		var event struct {
			opensslEvent
			ProcessID string `json:"process_id"`
		}
		if err := json.Unmarshal(buffer[:n], &event); err != nil {
			continue
		}
		identity, err := processIdentity("/proc", int(credentials.Pid))
		if err != nil || identity != event.ProcessID || event.Protocol != "traffic-openssl-v1" {
			s.mu.Lock()
			s.stats.TLSDropped++
			s.mu.Unlock()
			continue
		}
		if event.Type != "data" && event.Type != "loss" && event.Type != "close" {
			continue
		}
		if event.Type != "loss" && !strings.HasPrefix(event.Connection, strconv.Itoa(int(credentials.Pid))+"-") {
			continue
		}
		assembler := assemblers[identity]
		if assembler == nil {
			oldIDs := make([]string, 0, len(assemblers))
			for id := range assemblers {
				oldIDs = append(oldIDs, id)
			}
			sort.Strings(oldIDs)
			for _, id := range oldIDs {
				old := assemblers[id]
				live, err := processIdentity("/proc", old.pid)
				if err != nil || live != id {
					if err := p.record("preload/"+id, "openssl-preload", old.target, session.RawEvent{Type: "end", Reason: "target_exited"}); err != nil {
						return err
					}
					delete(assemblers, id)
				}
			}
			if len(assemblers) >= 256 {
				s.mu.Lock()
				s.stats.TLSDropped++
				s.mu.Unlock()
				continue
			}
			assembler = &rawTarget{pid: int(credentials.Pid), target: session.Target{PID: int(credentials.Pid), ID: identity, Service: "openssl"}}
			assemblers[identity] = assembler
			target, err := processTarget("/proc", assembler.pid)
			if err == nil {
				populateTarget("/proc", &target)
				if target.Service == "unknown" {
					target.Service = "openssl"
				}
				target.State = "active-preload"
				assembler.target = target
				s.mu.Lock()
				var active []session.Target
				for _, previous := range s.stats.Targets {
					if assemblers[previous.ID] != nil && previous.ID != identity {
						active = append(active, previous)
					}
				}
				s.stats.Targets = append(active, target)
				s.mu.Unlock()
			}
		}
		if event.Sequence > 0 {
			if assembler.lastSequence > 0 && event.Sequence != assembler.lastSequence+1 {
				reason, unit, count := sequenceDiscontinuity(assembler.lastSequence, event.Sequence)
				s.gap("openssl-preload", identity, reason, unit, count)
				if err := p.record("preload/"+identity, "openssl-preload", assembler.target, session.RawEvent{Type: "loss", Reason: reason, Unit: unit, Count: count}); err != nil {
					return err
				}
			}
			assembler.lastSequence = event.Sequence
		}
		if err := p.openssl("preload/"+identity, "openssl-preload", assembler.target, event.opensslEvent); err != nil {
			return err
		}
		s.mu.Lock()
		s.stats.TLS = "active-preload"
		s.mu.Unlock()
	}
	exitRecorded = true
	if drainTimedOut {
		s.gap("openssl-preload", path, "drain_timeout", "shutdowns", 1)
		s.gap("openssl-preload", path, "drain_unconfirmed", "shutdowns", 1)
		s.recordProbeExit("openssl-preload", session.ProbeExit{
			DataDrained:       false,
			TransportDetached: false,
			RuntimeState:      "preload socket drain timed out; in-process sender final sequence unconfirmed",
		})
		return nil
	}
	if stopAcceptErr != nil {
		s.problem(fmt.Errorf("preload socket shutdown: %w", stopAcceptErr))
	}
	// Preload lives inside independent service processes without a reverse
	// stop/final-sequence channel; keep DataDrained=false (unverified) even
	// after draining the local kernel socket queue.
	s.gap("openssl-preload", path, "drain_unconfirmed", "shutdowns", 1)
	runtimeState := "preload socket queue drained; in-process sender final sequence unconfirmed"
	if !socketDrained || stopAcceptErr != nil {
		runtimeState = "preload socket closed; in-process sender final sequence unconfirmed"
	}
	s.recordProbeExit("openssl-preload", session.ProbeExit{
		DataDrained:       false,
		TransportDetached: socketDrained && stopAcceptErr == nil,
		RuntimeState:      runtimeState,
	})
	return nil
}
