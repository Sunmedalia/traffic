package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func emit(v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		panic(e)
	}
	fmt.Println(string(b))
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	syscall.Umask(0077)
	if len(os.Args) < 2 {
		return errors.New("usage: traffic doctor|capture|analyze|status|requests|events|show|export|rules")
	}
	if os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		fmt.Println("traffic doctor|capture|analyze|status|requests|events|show|export|rules; use COMMAND --help for flags")
		return nil
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	id := ""
	if (cmd == "show" || cmd == "export" || cmd == "analyze") && len(args) > 0 {
		id = args[0]
		args = args[1:]
	}
	if cmd == "rules" {
		if len(args) != 2 || args[0] != "check" {
			return errors.New("usage: traffic rules check FILE")
		}
		if e := loadRules(args[1]); e != nil {
			return e
		}
		emit(map[string]any{"valid": true, "rules": len(rules)})
		return nil
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dir := fs.String("session", "", "session directory")
	output := fs.String("output", "", "capture output directory")
	out := fs.String("out", "", "export archive")
	ports := fs.String("ports", "80,443", "TCP ports")
	interfaces := fs.String("interfaces", "", "comma-separated interfaces")
	pid := fs.Int("pid", 0, "Nginx worker PID; default auto-discovered worker UID")
	ecapture := fs.String("ecapture", "/opt/traffic/bin/ecapture", "eCapture v2.9.1 binary")
	lib := fs.String("libssl", "/lib/aarch64-linux-gnu/libssl.so.3", "TLS library")
	ruleFile := fs.String("rules", "", "additional YAML rules")
	noTLS := fs.Bool("no-tls", false, "disable TLS probes")
	duration := fs.Duration("duration", 0, "optional capture duration")
	limit := fs.Int("limit", 100, "maximum results")
	client := fs.String("client", "", "source address filter")
	rule := fs.String("rule", "", "rule ID filter")
	since := fs.String("since", "", "RFC3339 start time")
	severity := fs.String("severity", "", "severity filter")
	fs.IntVar(&requestLimit, "request-limit", requestLimit, "maximum saved request body bytes")
	fs.IntVar(&responseLimit, "response-limit", responseLimit, "maximum saved response body bytes")
	fs.IntVar(&diskLimitMiB, "disk-limit-mib", diskLimitMiB, "session disk budget MiB")
	fs.DurationVar(&retention, "retention", retention, "transaction retention")
	fs.DurationVar(&scanWindow, "scan-window", scanWindow, "scan aggregation window")
	fs.IntVar(&scanThreshold, "scan-paths", scanThreshold, "distinct paths for scan detection")
	fs.BoolVar(&noDetect, "no-detect", false, "capture without attack detection")
	fs.Bool("json", false, "JSON output (default)")
	if e := fs.Parse(args); e != nil {
		if e == flag.ErrHelp {
			return nil
		}
		return e
	}
	if requestLimit < 1 || requestLimit > 1<<20 || responseLimit < 1 || responseLimit > 1<<20 || diskLimitMiB < 64 || retention <= 0 || scanWindow <= 0 || scanThreshold < 1 || *limit < 1 {
		return errors.New("invalid resource or result limits")
	}
	if *since != "" {
		stamp, e := time.Parse(time.RFC3339, *since)
		if e != nil {
			return fmt.Errorf("--since: %w", e)
		}
		*since = stamp.UTC().Format(indexTimeFormat)
	}
	if e := loadRules(*ruleFile); e != nil {
		return e
	}
	if cmd == "doctor" {
		devices, e := pcap.FindAllDevs()
		if e != nil {
			return e
		}
		maps, _ := exec.Command("sh", "-c", "for p in $(pgrep -x nginx); do echo PID=$p; grep libssl /proc/$p/maps | head -1; done").Output()
		_, btf := os.Stat("/sys/kernel/btf/vmlinux")
		_, probe := os.Stat(*ecapture)
		emit(map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "root": os.Geteuid() == 0, "btf": btf == nil, "ecapture_installed": probe == nil, "nginx": string(maps), "interfaces": devices, "tls_verified": false})
		return nil
	}
	if cmd == "capture" || cmd == "analyze" {
		if *output == "" {
			return errors.New("--output required")
		}
		if cmd == "analyze" && id == "" {
			return errors.New("PCAP path required")
		}
		debug.SetMemoryLimit(220 << 20)
		if e := os.MkdirAll(*output, 0700); e != nil {
			return e
		}
		lock, e := os.OpenFile(filepath.Join(*output, "capture.lock"), os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			return e
		}
		defer lock.Close()
		if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
			return fmt.Errorf("session is locked: %w", e)
		}
		defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		if _, e := os.Stat(filepath.Join(*output, "index.sqlite")); e == nil {
			return errors.New("output already contains a session; choose a new directory")
		}
		s, e := openStore(*output, true)
		if e != nil {
			return e
		}
		defer s.db.Close()
		p := newHTTP(s)
		if cmd == "capture" {
			cleanup, e := limitResources()
			if e != nil {
				s.stats.ResourceLimits = "unavailable"
				s.problem(fmt.Errorf("resource limits: %w", e))
			} else {
				s.stats.ResourceLimits = "cgroup-v2: 256MiB, 50% of one CPU"
				defer cleanup()
			}
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if *duration > 0 {
			var stop context.CancelFunc
			ctx, stop = context.WithTimeout(ctx, *duration)
			defer stop()
		}
		filterParts := []string{}
		for _, port := range strings.Split(*ports, ",") {
			n, e := strconv.Atoi(port)
			if e != nil || n < 1 || n > 65535 {
				return fmt.Errorf("invalid port %q", port)
			}
			filterParts = append(filterParts, fmt.Sprintf("port %d", n))
		}
		filter := "tcp and (" + strings.Join(filterParts, " or ") + ")"
		if cmd == "analyze" {
			e = capturePackets(ctx, s, p, "offline", filter, id)
			p.wg.Wait()
			s.mu.Lock()
			s.stats.State = "complete"
			s.mu.Unlock()
			s.report()
			return e
		}
		manifest := map[string]any{"schema_version": 1, "started": time.Now().UTC(), "filter": filter, "ecapture_version": "v2.9.1+traffic.1", "rules": rules, "header_limit": 32768, "request_limit": requestLimit, "response_limit": responseLimit}
		if file, e := os.Open(*ecapture); e == nil {
			hash := sha256.New()
			if _, e = io.Copy(hash, file); e == nil {
				manifest["ecapture_sha256"] = hex.EncodeToString(hash.Sum(nil))
			}
			file.Close()
		}
		b, _ := json.MarshalIndent(manifest, "", "  ")
		if err := os.WriteFile(filepath.Join(s.dir, "manifest.json"), b, 0600); err != nil {
			return err
		}
		names := strings.Split(*interfaces, ",")
		if *interfaces == "" {
			names = []string{"any"}
		}
		var wg sync.WaitGroup
		for _, name := range names {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				if e := capturePackets(ctx, s, p, name, filter, ""); e != nil {
					s.fail(e)
					cancel()
				}
			}(name)
		}
		if !*noTLS {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for attempt := 0; attempt < 2; attempt++ {
					err := captureTLS(ctx, s, p, *ecapture, *lib, *pid)
					if err == nil || ctx.Err() != nil {
						return
					}
					s.problem(err)
					s.mu.Lock()
					s.stats.TLS = "unavailable"
					s.mu.Unlock()
					p.mu.Lock()
					for key := range p.pending {
						if strings.HasPrefix(key, "tls:") {
							delete(p.pending, key)
						}
					}
					for key := range p.responses {
						if strings.HasPrefix(key, "tls:") {
							delete(p.responses, key)
						}
					}
					p.mu.Unlock()
				}
			}()
		}
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case <-ticker.C:
				s.report()
				s.mu.Lock()
				fatal := s.fatal
				s.mu.Unlock()
				if fatal != nil {
					cancel()
				}
				if e := maintain(s); e != nil {
					s.fail(e)
					cancel()
				}
			}
		}
		cancel()
		wg.Wait()
		p.wg.Wait()
		s.mu.Lock()
		s.stats.State = "stopped"
		s.mu.Unlock()
		s.report()
		emit(s.stats)
		return s.fatal
	}
	if *dir == "" {
		return errors.New("--session required")
	}
	if cmd == "status" {
		b, e := os.ReadFile(filepath.Join(*dir, "status.json"))
		if e != nil {
			return e
		}
		var status map[string]any
		if json.Unmarshal(b, &status) == nil {
			if info, e := os.Stat(filepath.Join(*dir, "status.json")); e == nil && time.Since(info.ModTime()) > 5*time.Second && status["state"] == "running" {
				status["state"] = "stale"
				status["note"] = "capture heartbeat missing; inspect process and logs"
			}
			emit(status)
		} else {
			return fmt.Errorf("invalid status JSON")
		}
		return nil
	}
	s, e := openStore(*dir, false)
	if e != nil {
		return e
	}
	defer s.db.Close()
	if cmd == "show" || cmd == "export" {
		var b []byte
		if e = s.db.QueryRow("SELECT data FROM requests WHERE id=?", id).Scan(&b); e != nil {
			return e
		}
		var t Transaction
		if e = json.Unmarshal(b, &t); e != nil {
			return e
		}
		if cmd == "show" {
			decoded, decodedView := decodedBody(t.Request)
			emit(map[string]any{"transaction": t, "request_text": safeText(t.Request), "response_text": safeText(t.Response), "decoded_body": decoded, "decoded_view": decodedView})
			return nil
		}
		if *out == "" {
			return errors.New("--out required")
		}
		return exportEvidence(s, t, b, *out)
	}
	if cmd != "requests" && cmd != "events" {
		return fmt.Errorf("unknown command %s", cmd)
	}
	prefix := *client + ":%"
	if net.ParseIP(*client) != nil && strings.Contains(*client, ":") {
		prefix = "[" + *client + "]:%"
	}
	query := "SELECT data FROM requests WHERE time>=? AND (?='' OR client=? OR client LIKE ?)"
	if cmd == "events" {
		query += " AND alert>0"
	}
	query += " ORDER BY time DESC"
	rows, e := s.db.Query(query, *since, *client, *client, prefix)
	if e != nil {
		return e
	}
	defer rows.Close()
	result := []Transaction{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return e
		}
		var t Transaction
		if e = json.Unmarshal(b, &t); e != nil {
			return e
		}
		if cmd == "events" && len(t.Alerts) == 0 {
			continue
		}
		if *rule != "" || *severity != "" {
			match := false
			for _, a := range t.Alerts {
				if (*rule == "" || a.Rule == *rule) && (*severity == "" || a.Severity == *severity) {
					match = true
				}
			}
			if !match {
				continue
			}
		}
		t.Request = nil
		t.Response = nil
		result = append(result, t)
		if len(result) >= *limit {
			break
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	emit(result)
	return nil
}
func maintain(s *Store) error {
	if _, e := s.db.Exec("DELETE FROM requests WHERE time < ?", time.Now().UTC().Add(-retention).Format(indexTimeFormat)); e != nil {
		return e
	}
	var total int64
	filepath.Walk(s.dir, func(_ string, i os.FileInfo, e error) error {
		if e == nil && !i.IsDir() {
			total += i.Size()
		}
		return nil
	})
	if total > int64(diskLimitMiB)<<20 {
		return errors.New("session exceeds disk budget; capture stopped")
	}
	var stat syscall.Statfs_t
	if e := syscall.Statfs(s.dir, &stat); e != nil {
		return e
	}
	if stat.Bavail*uint64(stat.Bsize) < 512<<20 {
		return errors.New("less than 512 MiB free; capture stopped")
	}
	return nil
}
func exportEvidence(s *Store, t Transaction, b []byte, path string) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	z := zip.NewWriter(f)
	hashes := map[string]string{}
	add := func(name string, data []byte) error {
		w, e := z.Create(name)
		if e != nil {
			return e
		}
		if _, e = w.Write(data); e != nil {
			return e
		}
		h := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(h[:])
		return nil
	}
	for name, data := range map[string][]byte{"event.json": b, "request.http": t.Request, "response.http": t.Response} {
		if e = add(name, data); e != nil {
			return e
		}
	}
	note := map[string]any{"schema_version": 1, "source": t.Source, "incomplete": t.Incomplete, "truncated": t.Truncated, "packet_scope": "client endpoint and 120-second window; may include other requests on the same connection; original packets may have rotated", "tls_plaintext_source": "process hook; network PCAP remains encrypted"}
	info, _ := json.MarshalIndent(note, "", "  ")
	if e = add("evidence.json", info); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(s.dir, "capture.lock"), os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); e != nil {
		return fmt.Errorf("stop capture before exporting evidence: %w", e)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	host, port, e := net.SplitHostPort(t.Client)
	if e == nil {
		files, _ := filepath.Glob(filepath.Join(s.dir, "packets-*.pcap"))
		for _, name := range files {
			handle, e := pcap.OpenOffline(name)
			if e != nil {
				return e
			}
			filter := fmt.Sprintf("tcp and host %s and port %s", host, port)
			if e = handle.SetBPFFilter(filter); e != nil {
				handle.Close()
				return e
			}
			entry := filepath.Base(name)
			w, e := z.Create(entry)
			if e != nil {
				handle.Close()
				return e
			}
			hash := sha256.New()
			writer := pcapgo.NewWriter(io.MultiWriter(w, hash))
			if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
				handle.Close()
				return err
			}
			for {
				data, ci, err := handle.ReadPacketData()
				if err != nil {
					if err != io.EOF {
						handle.Close()
						return err
					}
					break
				}
				if ci.Timestamp.Before(t.Time.Add(-60*time.Second)) || ci.Timestamp.After(t.Time.Add(60*time.Second)) {
					continue
				}
				if err = writer.WritePacket(ci, data); err != nil {
					handle.Close()
					return err
				}
			}
			handle.Close()
			hashes[entry] = hex.EncodeToString(hash.Sum(nil))
		}
	}
	h, _ := json.MarshalIndent(hashes, "", "  ")
	if e = add("sha256.json", h); e != nil {
		return e
	}
	if e = z.Close(); e != nil {
		return e
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
