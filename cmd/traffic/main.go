package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
)

func emit(v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		panic(e)
	}
	fmt.Println(string(b))
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	syscall.Umask(0077)
	if len(args) == 0 {
		return errors.New("usage: traffic doctor|capture|import|rules")
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("traffic doctor|capture|import|rules; use COMMAND --help for flags")
		return nil
	}
	cmd, args := args[0], args[1:]
	id := ""
	if cmd == "import" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id = args[0]
		args = args[1:]
	}
	if cmd != "doctor" && cmd != "capture" && cmd != "import" && cmd != "rules" {
		return fmt.Errorf("unknown collector command %q; use traffic-tui for session analysis", cmd)
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
	output := fs.String("output", "", "capture output directory")
	ports := fs.String("ports", "80,443", "TCP ports")
	interfaces := fs.String("interfaces", "", "comma-separated interfaces")
	pid := fs.Int("pid", 0, "Nginx worker PID; default auto-discovered worker UID")
	ecapture := fs.String("ecapture", "/opt/traffic/bin/ecapture", "eCapture v2.9.1 binary")
	lib := fs.String("libssl", "/lib/aarch64-linux-gnu/libssl.so.3", "TLS library")
	ruleFile := fs.String("rules", "", "additional YAML rules")
	noTLS := fs.Bool("no-tls", false, "disable TLS probes")
	duration := fs.Duration("duration", 0, "optional capture duration")
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
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if requestLimit < 1 || requestLimit > 1<<20 || responseLimit < 1 || responseLimit > 1<<20 || diskLimitMiB < 64 || retention <= 0 || scanWindow <= 0 || scanThreshold < 1 {
		return errors.New("invalid resource or result limits")
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
	if cmd == "capture" || cmd == "import" {
		if *output == "" {
			return errors.New("--output required")
		}
		if cmd == "import" && id == "" {
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
		if cmd == "import" {
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
	return fmt.Errorf("unknown command %s", cmd)
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
