package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Sunmedalia/traffic/internal/session"
)

// The socket is private to the collector UID. Kernel credentials identify every
// sender, and /proc start time prevents PID reuse from merging TLS connections.
func openPreloadSocket(path string) (*net.UnixConn, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("--openssl-preload-socket must be absolute")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, fmt.Errorf("preload socket path must not exist: %s", path)
	}
	connection, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	cleanup := func(err error) (*net.UnixConn, error) { connection.Close(); os.Remove(path); return nil, err }
	if err := os.Chmod(path, 0600); err != nil {
		return cleanup(err)
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

func capturePreload(ctx context.Context, s *Store, p *HTTPProcessor, path string) error {
	connection, err := openPreloadSocket(path)
	if err != nil {
		return err
	}
	defer connection.Close()
	defer os.Remove(path)
	directory := filepath.Join(s.dir, "tls")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	evidence, err := os.OpenFile(filepath.Join(directory, "openssl-preload.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer evidence.Close()
	encoder := json.NewEncoder(evidence)
	assemblers := map[string]*opensslAssembler{}
	defer func() {
		for _, assembler := range assemblers {
			if err := assembler.close(""); err != nil {
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
				for _, assembler := range assemblers {
					assembler.frames.expire(time.Now(), false, p, "")
				}
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
		if credentials == nil || credentials.Uid != uint32(os.Geteuid()) {
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
					if err := old.close(""); err != nil {
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
			assembler = &opensslAssembler{processor: p, frames: &Frames{}, prefix: "preload/" + identity + "/", pid: int(credentials.Pid)}
			assemblers[identity] = assembler
			target, err := processTarget("/proc", assembler.pid)
			if err == nil {
				populateTarget("/proc", &target)
				if target.Service == "unknown" {
					target.Service = "openssl"
				}
				target.State = "active-preload"
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
		if err := encoder.Encode(event); err != nil {
			return err
		}
		if err := assembler.ingest(event.opensslEvent); err != nil {
			return fmt.Errorf("preload event: %w", err)
		}
		s.mu.Lock()
		s.stats.TLS = "active-preload"
		s.mu.Unlock()
	}
	return nil
}
