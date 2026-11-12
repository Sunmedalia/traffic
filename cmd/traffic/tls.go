package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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
func captureTLS(ctx context.Context, s *Store, p *HTTPProcessor, bin, lib string, pid int) error {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	addr := listener.Addr().String()
	listener.Close()
	args := []string{"tls", "--libssl", lib, "--mapsize", "1024", "--ecaptureq", "ws://" + addr + "/"}
	if pid > 0 {
		args = append(args, "-p", strconv.Itoa(pid))
	} else {
		uid, err := nginxUID()
		if err != nil {
			return err
		}
		args = append(args, "-u", strconv.Itoa(uid))
	}
	for _, name := range []string{"logs", "tls"} {
		if err := os.MkdirAll(filepath.Join(s.dir, name), 0700); err != nil {
			return err
		}
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
	ws.SetReadLimit(2 << 20)
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			ws.Close()
		case <-watchDone:
		}
	}()
	s.mu.Lock()
	s.stats.TLS = "attached"
	s.mu.Unlock()
	events, err := os.OpenFile(filepath.Join(s.dir, "tls", "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer events.Close()
	enc := json.NewEncoder(events)
	frames := &Frames{}
	stopExpiry := frames.startExpiry(ctx, p)
	defer stopExpiry()
	for {
		_, b, e := ws.ReadMessage()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		outer, _, e := protoFields(b)
		if e != nil {
			return e
		}
		if outer[2] == nil {
			continue
		}
		fields, nums, e := protoFields(outer[2])
		if e != nil {
			return e
		}
		if string(fields[8]) != "nginx" {
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
		frames.ingest(key+string(fields[14]), payload, frameContext{connection: key, client: client, pid: int(nums[7])}, head, p)
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
