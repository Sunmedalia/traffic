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
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
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
func run(args []string) (runErr error) {
	session.PrivateUmask()
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
	output := fs.String("output", "", "exact session directory; default is auto-created under --data-dir")
	dataDir := fs.String("data-dir", "./sessions", "root directory for automatically named sessions")
	name := fs.String("name", "", "session name; default capture or import")
	ports := fs.String("ports", "80,443", "TCP ports")
	interfaces := fs.String("interfaces", "", "comma-separated interfaces")
	fs.StringVar(&iisProbe, "iis-probe", "", "Windows IIS plaintext helper script; explicit opt-in")
	fs.StringVar(&iisPython, "iis-python", "python", "Python executable with Frida installed")
	fs.StringVar(&iisRuntime, "iis-runtime-dir", "", "probe runtime directory readable by the target process identity")
	fs.StringVar(&iisPython, "probe-python", "python", "Python executable for Windows plaintext helpers (alias of --iis-python)")
	fs.StringVar(&iisRuntime, "probe-runtime-dir", "", "temporary directory readable by Windows probe targets (alias of --iis-runtime-dir)")
	fs.StringVar(&opensslProbe, "openssl-probe", "", "Windows OpenSSL plaintext helper script; explicit opt-in")
	fs.StringVar(&opensslProfile, "openssl-profile", "", "Windows static OpenSSL binary profile JSON; default bundled profiles")
	javaAttach := fs.Bool("java-attach", false, "explicitly attach Java agent to --pid")
	javaPID := fs.Int("java-pid", 0, "explicit JVM PID for Java attach while auto-discovering other services")
	javaHelper := fs.String("java-helper", "", "Java executable with jdk.attach; default target executable")
	javaAgent := fs.String("java-agent", "/opt/traffic/bin/traffic-java-agent.jar", "Java agent archive")
	service := fs.String("service", "auto", "service: auto, iis (Windows), nginx, apache, tomcat, openssl")
	pid := fs.Int("pid", 0, "target process PID; default discover service processes")
	ecapture := fs.String("ecapture", "/opt/traffic/bin/ecapture", "eCapture v2.9.1 binary")
	lib := fs.String("libssl", "", "TLS library override; Windows module name or Linux library path")
	ruleFile := fs.String("rules", "", "additional YAML rules")
	proxyList := fs.String("trusted-proxies", "", "comma-separated trusted proxy IPs or CIDRs for X-Forwarded-For / X-Real-IP")
	webhookURL := fs.String("alert-webhook", "", "POST alert JSON to HTTP(S) endpoint; optional TRAFFIC_WEBHOOK_TOKEN bearer token")
	preloadSocket := fs.String("openssl-preload-socket", "", "Linux Unix datagram socket for LD_PRELOAD OpenSSL events")
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
	var proxyErr error
	trustedProxies, proxyErr = parseTrustedProxies(*proxyList)
	if proxyErr != nil {
		return proxyErr
	}
	if err := validateWebhook(*webhookURL); err != nil {
		return err
	}
	if *preloadSocket != "" && (runtime.GOOS != "linux" || cmd != "capture" || *noTLS || *javaAttach || *pid != 0 || *service != "auto") {
		return errors.New("--openssl-preload-socket requires Linux capture with auto service, no --pid, and TLS enabled without Java attach")
	}
	if *pid < 0 || *javaPID < 0 {
		return errors.New("PID must not be negative")
	}
	if *javaAttach && *service != "auto" && *service != "tomcat" {
		return errors.New("--java-attach requires auto or tomcat service")
	}
	if *javaAttach && *pid <= 0 && *javaPID <= 0 {
		return errors.New("--java-attach requires --pid or --java-pid")
	}
	if *javaPID > 0 && (!*javaAttach || (*pid > 0 && *pid != *javaPID)) {
		return errors.New("--java-pid requires --java-attach and must agree with --pid when both are set")
	}
	if *javaAttach && *noTLS {
		return errors.New("--java-attach conflicts with --no-tls")
	}
	if *service != "auto" && *service != "nginx" && *service != "apache" && *service != "tomcat" && *service != "openssl" && *service != "iis" {
		return errors.New("invalid service")
	}
	if runtime.GOOS == "windows" && (*javaAttach || *service == "tomcat") {
		return errors.New("Windows Java attach is unavailable")
	}
	if runtime.GOOS != "windows" && (iisProbe != "" || opensslProbe != "" || opensslProfile != "") {
		return errors.New("Windows probe flags require Windows")
	}
	if iisProbe != "" && (iisRuntime == "" || *noTLS) {
		return errors.New("--iis-probe requires --iis-runtime-dir and conflicts with --no-tls")
	}
	if opensslProbe != "" && (iisRuntime == "" || *noTLS) {
		return errors.New("--openssl-probe requires --probe-runtime-dir and conflicts with --no-tls")
	}
	if opensslProfile != "" && opensslProbe == "" {
		return errors.New("--openssl-profile requires --openssl-probe")
	}
	if runtime.GOOS != "windows" && *service == "iis" {
		return errors.New("iis service requires Windows")
	}
	if *javaAttach {
		selectedJavaPID := *javaPID
		if selectedJavaPID == 0 {
			selectedJavaPID = *pid
		}
		target, err := processTarget("/proc", selectedJavaPID)
		if err != nil {
			return fmt.Errorf("Java target: %w", err)
		}
		if target.Service != "tomcat" {
			return errors.New("Java probe currently supports standalone Tomcat targets")
		}
	}
	if *service == "openssl" && *pid <= 0 {
		return errors.New("openssl service requires --pid")
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
		emit(doctorReport(devices, *service, *pid, *lib, *ecapture))
		return nil
	}
	if cmd == "capture" || cmd == "import" {
		if cmd == "import" && id == "" {
			return errors.New("PCAP path required")
		}
		// Validate inputs before reserving a session directory.
		filterParts := []string{}
		capturePorts = map[int]bool{}
		for _, port := range strings.Split(*ports, ",") {
			number, err := strconv.Atoi(port)
			if err != nil || number < 1 || number > 65535 {
				return fmt.Errorf("invalid port %q", port)
			}
			capturePorts[number] = true
			filterParts = append(filterParts, fmt.Sprintf("port %d", number))
		}
		filter := "tcp and (" + strings.Join(filterParts, " or ") + ")"
		names, err := captureInterfaces(*interfaces, cmd == "import")
		if err != nil {
			return err
		}

		if cmd == "import" {
			handle, err := pcap.OpenOffline(id)
			if err != nil {
				return err
			}
			handle.Close()
		}
		dataDirSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "data-dir" {
				dataDirSet = true
			}
		})
		if *output != "" && dataDirSet {
			return errors.New("use either --output or --data-dir")
		}
		if *name == "" {
			*name = cmd
		}
		host, err := os.Hostname()
		if err != nil {
			return err
		}
		started := time.Now()
		directory, err := prepareOutputDir(*output, *dataDir, *name, host, started)
		if err != nil {
			return err
		}
		*output = directory
		debug.SetMemoryLimit(220 << 20)
		lock, e := os.OpenFile(filepath.Join(*output, "capture.lock"), os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			return e
		}
		defer lock.Close()
		if e = session.LockFile(lock, true); e != nil {
			return fmt.Errorf("session is locked: %w", e)
		}
		defer session.UnlockFile(lock)
		if _, e := os.Stat(filepath.Join(*output, "index.sqlite")); e == nil {
			return errors.New("output already contains a session; choose a new directory")
		}
		s, e := openStore(*output, true)
		if e != nil {
			return e
		}
		defer s.db.Close()
		if *webhookURL != "" {
			s.webhook = newAlertWebhook(s, *webhookURL, os.Getenv("TRAFFIC_WEBHOOK_TOKEN"))
			defer func() { s.webhook.close(); s.report() }()
		}
		defer func() {
			if runErr != nil {
				s.mu.Lock()
				alreadyReported := s.fatal != nil
				s.stats.State = "failed"
				s.mu.Unlock()
				if !alreadyReported {
					s.problem(runErr)
				}
				s.report()
			}
		}()
		s.stats.Started = started.UTC()
		s.stats.TLSCoverage = "unverified"
		s.problem(errors.New(session.CoverageWarning))
		fmt.Fprintf(os.Stderr, "会话目录 %s\n", s.dir)
		s.report()
		s.stats.Targets = discoverTargets("/proc", *service, *pid, *lib)
		p := newHTTP(s)
		if cmd == "capture" {
			cleanup, e := limitResources()
			if e != nil {
				s.stats.ResourceLimits = "unavailable"
				s.problem(fmt.Errorf("resource limits: %w", e))
			} else {
				s.stats.ResourceLimits = resourceLimitDescription()
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
		manifest := map[string]any{
			"schema_version":         1,
			"layout_version":         2,
			"hostname":               host,
			"os":                     runtime.GOOS,
			"arch":                   runtime.GOARCH,
			"name":                   *name,
			"mode":                   cmd,
			"started":                s.stats.Started,
			"filter":                 filter,
			"interfaces":             names,
			"service":                *service,
			"targets":                discoverTargets("/proc", *service, *pid, *lib),
			"tls_enabled":            cmd == "capture" && !*noTLS,
			"rules":                  rules,
			"trusted_proxies":        trustedProxies,
			"openssl_preload_socket": *preloadSocket,
			"tls_coverage":           "unverified",
			"tls_missing_estimate":   nil,
			"header_limit":           32768,
			"request_limit":          requestLimit,
			"response_limit":         responseLimit,
		}
		if cmd == "import" {
			manifest["input_pcap"] = id
		}
		if cmd == "capture" && !*noTLS && *preloadSocket == "" && runtime.GOOS != "windows" {
			manifest["ecapture_version"] = "external; identified by ecapture_sha256"
			if file, e := os.Open(*ecapture); e == nil {
				hash := sha256.New()
				if _, e = io.Copy(hash, file); e == nil {
					manifest["ecapture_sha256"] = hex.EncodeToString(hash.Sum(nil))
				}
				file.Close()
			}
		}
		b, _ := json.MarshalIndent(manifest, "", "  ")
		if err := os.WriteFile(filepath.Join(s.dir, "manifest.json"), b, 0600); err != nil {
			return err
		}
		s.report()
		if cmd == "import" {
			e = capturePackets(ctx, s, p, "offline", filter, id)
			p.wg.Wait()
			if e != nil {
				return e
			}
			s.mu.Lock()
			s.stats.State = "complete"
			s.mu.Unlock()
			if s.webhook != nil {
				s.webhook.close()
			}
			s.report()
			return nil
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
				if *preloadSocket != "" {
					if err := capturePreload(ctx, s, p, *preloadSocket); err != nil {
						s.fail(err)
						cancel()
					}
				} else {
					captureServices(ctx, s, p, *ecapture, *lib, *service, *pid, *javaAttach, *javaAgent, *javaHelper, *javaPID)
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
				if *noTLS {
					targets := discoverTargets("/proc", *service, *pid, *lib)
					for i := range targets {
						targets[i].State = "http-only"
					}
					s.mu.Lock()
					s.stats.Targets = targets
					s.mu.Unlock()
				}
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
		if s.fatal != nil {
			s.stats.State = "failed"
		}
		s.mu.Unlock()
		if s.webhook != nil {
			s.webhook.close()
		}
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
	free, err := session.FreeBytes(s.dir)
	if err != nil {
		return err
	}
	if free < 512<<20 {
		return errors.New("less than 512 MiB free; capture stopped")
	}

	return nil
}
