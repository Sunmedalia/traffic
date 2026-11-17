package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
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

func capturePreload(ctx context.Context, s *Store, p *eventRecorder, path string, allowedUIDs []uint32) error {
	connection, err := openPreloadSocket(path, allowedUIDs)
	if err != nil {
		return err
	}
	defer connection.Close()
	defer os.Remove(path)
	type rawTarget struct {
		pid    int
		target session.Target
	}
	assemblers := map[string]*rawTarget{}
	defer func() {
		for id, a := range assemblers {
			if err := p.record("preload/"+id, "openssl-preload", a.target, session.RawEvent{Type: "end"}); err != nil {
				s.fail(err)
			}
		}
	}()
	buffer := make([]byte, 32768)
	ancillary := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	s.mu.Lock()
	s.stats.TLS = "listening-preload"
	s.mu.Unlock()
	s.report()
	for ctx.Err() == nil {
		connection.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, oobn, flags, _, err := connection.ReadMsgUnix(buffer, ancillary)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return err
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
			for id, old := range assemblers {
				live, err := processIdentity("/proc", old.pid)
				if err != nil || live != id {
					if err := p.record("preload/"+id, "openssl-preload", old.target, session.RawEvent{Type: "end"}); err != nil {
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
		if err := p.openssl("preload/"+identity, "openssl-preload", assembler.target, event.opensslEvent); err != nil {
			return err
		}
		s.mu.Lock()
		s.stats.TLS = "active-preload"
		s.mu.Unlock()
	}
	return nil
}
