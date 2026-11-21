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
	if _, _, help := helpRequest(os.Args[1:]); !help {
		if err := session.InitRuntime(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) (runErr error) {
	session.PrivateUmask()
	helpCommand, cnHelp, wantsHelp := helpRequest(args)
	if len(args) == 0 || (wantsHelp && helpCommand == "") {
		printCollectorHelp(os.Stdout, "", cnHelp, nil)
		return nil
	}
	if wantsHelp {
		args = []string{helpCommand}
	}
	cmd, args := args[0], args[1:]
	if cmd == "rules" {
		return errors.New("rule validation moved to traffic-console rules check FILE")
	}
	id := ""
	if cmd == "import" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id = args[0]
		args = args[1:]
	}
	if cmd != "doctor" && cmd != "capture" && cmd != "import" {
		return fmt.Errorf("unknown collector command %q; use traffic-console for session analysis", cmd)
	}
	defaults := portableDefaults()
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.Usage = func() { printCollectorHelp(fs.Output(), cmd, false, fs) }
	output := fs.String("output", "", "exact session directory; default is auto-created under --data-dir")
	dataDir := fs.String("data-dir", session.DefaultDataDir(), "root directory for automatically named sessions")
	name := fs.String("name", "", "session name; default capture or import")
	fs.IntVar(&networkNamespacePID, "netns-pid", 0, "Linux target network namespace PID; open packet handles there without changing the target")
	ports := fs.String("ports", "80,443", "TCP ports")
	interfaces := fs.String("interfaces", "", "comma-separated interfaces")
	fs.StringVar(&iisProbe, "iis-probe", defaults.iis, "Windows IIS plaintext helper; bundled by default")
	fs.StringVar(&iisPython, "iis-python", defaults.python, "Python executable with Frida installed")
	fs.StringVar(&iisRuntime, "iis-runtime-dir", defaults.runtime, "probe runtime directory readable by the target process identity")
	fs.StringVar(&iisPython, "probe-python", defaults.python, "Python executable for Windows plaintext helpers (alias of --iis-python)")
	fs.StringVar(&iisRuntime, "probe-runtime-dir", defaults.runtime, "temporary directory readable by Windows probe targets (alias of --iis-runtime-dir)")
	fs.StringVar(&opensslProbe, "openssl-probe", defaults.openssl, "Windows OpenSSL plaintext helper; bundled by default")
	fs.StringVar(&opensslProfile, "openssl-profile", "", "Windows static OpenSSL binary profile JSON; default bundled profiles")
	javaAttach := fs.Bool("java-attach", false, "explicitly attach Java agent (Tomcat NIO, standalone or java -jar, JDK 8+) to --pid")
	javaPID := fs.Int("java-pid", 0, "explicit JVM PID for Java attach while auto-discovering other services")
	javaHelper := fs.String("java-helper", "", "JDK java executable with the attach API (jdk.attach, or lib/tools.jar on JDK 8); default target executable")
	javaAgent := fs.String("java-agent", session.BundleFile("deps/java/traffic-java-agent.jar", "/opt/traffic/bin/traffic-java-agent.jar"), "Java agent archive")
	service := fs.String("service", "auto", "service: auto, iis (Windows), nginx, apache, tomcat, openssl")
	pid := fs.Int("pid", 0, "target process PID; default discover service processes")
	ecapture := fs.String("ecapture", session.BundleFile("deps/ecapture/ecapture", "/opt/traffic/bin/ecapture"), "eCapture v2.9.1 binary")
	lib := fs.String("libssl", "", "TLS library override; Windows module name or Linux library path")
	proxyList := fs.String("trusted-proxies", "", "comma-separated trusted proxy IPs or CIDRs for X-Forwarded-For / X-Real-IP")
	preloadSocket := fs.String("openssl-preload-socket", "", "Linux Unix datagram socket for LD_PRELOAD OpenSSL events")
	preloadAllowUID := fs.String("openssl-preload-allow-uid", "", "comma-separated sender UIDs allowed to write preload events; opens the socket to their group")
	requirePlaintext := fs.Bool("require-plaintext", false, "fail unless an IIS probe records request-side plaintext; no HTTP reconstruction")
	requireTLS := fs.Bool("require-tls", false, "fail before capture if selected HTTPS targets fail read-only preflight")
	fs.IntVar(&collectorMemoryMiB, "collector-memory-mib", 256, "collector and helper memory budget MiB; excludes in-process probes")
	fs.IntVar(&collectorCPUPercent, "collector-cpu-percent", 50, "collector CPU budget as percent of one CPU")
	fs.DurationVar(&drainTimeout, "drain-timeout", 5*time.Second, "maximum probe data drain time")
	fs.DurationVar(&stopTimeout, "stop-timeout", 30*time.Second, "total shutdown budget after stop is requested; must be at least --drain-timeout")
	fs.StringVar(&evidenceBackpressure, "evidence-backpressure", string(evidenceBackpressureStrict), "raw evidence queue congestion policy: strict or drop")
	noTLS := fs.Bool("no-tls", false, "disable TLS probes")
	duration := fs.Duration("duration", 0, "optional capture duration")
	fs.IntVar(&diskLimitMiB, "disk-limit-mib", diskLimitMiB, "session disk budget MiB")
	fs.IntVar(&pcapBufferMiB, "pcap-buffer-mib", pcapBufferMiB, "kernel capture buffer MiB per libpcap interface")
	fs.Bool("no-detect", true, "deprecated compatibility flag; collection never runs detection")
	jsonUsage := "JSON output (default)"
	if cmd == "doctor" {
		jsonUsage = "print raw JSON instead of the readable diagnostic report"
	}
	jsonOutput := fs.Bool("json", false, jsonUsage)
	if wantsHelp {
		printCollectorHelp(os.Stdout, cmd, cnHelp, fs)
		return nil
	}
	if e := fs.Parse(args); e != nil {
		if e == flag.ErrHelp {
			return nil
		}
		return e
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if cmd == "doctor" {
		for name := range explicit {
			if !doctorHelpFlags[name] {
				return fmt.Errorf("--%s is not a doctor option; see traffic doctor --help", name)
			}
		}
	}
	if *noTLS {
		if !explicit["iis-probe"] {
			iisProbe = ""
		}
		if !explicit["openssl-probe"] {
			opensslProbe = ""
		}
	}
	var proxyErr error
	trustedProxies, proxyErr = parseTrustedProxies(*proxyList)
	if proxyErr != nil {
		return proxyErr
	}
	if *preloadSocket != "" && (runtime.GOOS != "linux" || cmd != "capture" || *noTLS || *javaAttach || *pid != 0 || *service != "auto") {
		return errors.New("--openssl-preload-socket requires Linux capture with auto service, no --pid, and TLS enabled without Java attach")
	}
	preloadUIDs, uidErr := parsePreloadUIDs(*preloadAllowUID)
	if uidErr != nil {
		return uidErr
	}
	if len(preloadUIDs) > 0 && *preloadSocket == "" {
		return errors.New("--openssl-preload-allow-uid requires --openssl-preload-socket")
	}
	if networkNamespacePID < 0 || (networkNamespacePID != 0 && (runtime.GOOS != "linux" || cmd == "import")) {
		return errors.New("--netns-pid requires Linux doctor or capture with a positive PID")
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
			return errors.New("Java probe supports standalone Tomcat or `java -jar` targets")
		}
	}
	if *service == "openssl" && *pid <= 0 {
		return errors.New("openssl service requires --pid")
	}
	if collectorMemoryMiB < 64 || collectorMemoryMiB > 65536 || collectorCPUPercent < 1 || collectorCPUPercent > 100 || drainTimeout <= 0 || drainTimeout > 15*time.Second || stopTimeout < drainTimeout || stopTimeout > 5*time.Minute {
		return errors.New("invalid collector resource or drain limits")
	}
	backpressurePolicy, backpressureErr := parseEvidenceBackpressurePolicy(evidenceBackpressure)
	if backpressureErr != nil {
		return backpressureErr
	}
	if *requireTLS && (*noTLS || cmd != "capture") {
		return errors.New("--require-tls requires capture with TLS enabled")
	}
	if *requirePlaintext && (*noTLS || cmd != "capture" || (*service != "iis" && *service != "auto")) {
		return errors.New("--require-plaintext requires capture with IIS TLS enabled")
	}
	if pcapBufferMiB < minPCAPBufferMiB || pcapBufferMiB > maxPCAPBufferMiB {
		return fmt.Errorf("--pcap-buffer-mib must be between %d and %d", minPCAPBufferMiB, maxPCAPBufferMiB)
	}
	if diskLimitMiB < 64 {
		return errors.New("invalid resource or result limits")
	}
	if cmd == "doctor" {
		capturePorts = map[int]bool{}
		for _, text := range strings.Split(*ports, ",") {
			port, err := strconv.Atoi(text)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid port %q", text)
			}
			capturePorts[port] = true
		}
		var devices []pcap.Interface
		e := inCaptureNamespace(func() error { var err error; devices, err = listCaptureDevices(); return err })
		if e != nil {
			return e
		}
		report := doctorReport(devices, *service, *pid, *lib, *ecapture)
		report["checks"] = captureChecks(*service, *pid, *lib, *ecapture, *javaAttach, *javaAgent, *preloadSocket, *javaPID)
		return writeDoctorOutput(os.Stdout, report, *ports, *jsonOutput)
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
		if cmd == "capture" && !*noTLS {
			if err := preparePortableProbeRuntime(); err != nil {
				return err
			}
		}
		var checks []captureCheck
		if cmd == "capture" && !*noTLS {
			checks = captureChecks(*service, *pid, *lib, *ecapture, *javaAttach, *javaAgent, *preloadSocket, *javaPID)
		}
		if *requireTLS {
			if err := requireCaptureChecks(checks); err != nil {
				return err
			}
		}
		filter := "tcp and (" + strings.Join(filterParts, " or ") + ")"
		names, err := captureInterfaces(*interfaces, cmd == "import")
		if err != nil {
			return err
		}

		if cmd == "import" {
			handle, err := openOfflinePacket(id)
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
		debug.SetMemoryLimit(int64(collectorMemoryMiB) * 220 / 256 << 20)
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
		s.probeCheck = func(target session.Target) captureCheck {
			java := *javaAttach && (*javaPID == 0 || *javaPID == target.PID)
			result := captureChecks(target.Service, target.PID, target.Library, *ecapture, java, *javaAgent, "", *javaPID)
			if len(result) == 0 {
				return captureCheck{Target: target.ID, Status: "unavailable", Reason: "target exited during preflight"}
			}
			return result[0]
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
		if cmd == "capture" {
			s.stats.State = "starting"
			s.stats.PacketInterfaces = map[string]string{}
			for _, name := range names {
				s.stats.PacketInterfaces[name] = "starting"
			}
		}
		s.stats.TLSCoverage = "unverified"
		s.problem(errors.New(session.CoverageWarning))
		fmt.Fprintf(os.Stderr, "会话目录 %s\n", s.dir)
		s.report()
		s.stats.Targets = discoverTargets("/proc", *service, *pid, *lib)
		p := newRecorderWithPolicy(s, backpressurePolicy)
		recorderFinalized := false
		defer func() {
			if !recorderFinalized {
				_ = p.close()
			}
		}()
		if cmd == "capture" {
			cleanup, e := limitResources()
			if e != nil {
				s.stats.ResourceLimits = "unavailable"
				s.problem(fmt.Errorf("resource limits: %w", e))
			} else {
				s.stats.ResourceLimits = resourceLimitDescription()
				defer cleanup()
				if e := checkMemoryBackedSession(s.dir); e != nil {
					return e
				}
			}
		}
		sigCtx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stopSig()
		ctx, cancel := context.WithCancel(sigCtx)
		defer cancel()
		var durationCtx context.Context
		if *duration > 0 {
			var stop context.CancelFunc
			durationCtx, stop = context.WithTimeout(context.Background(), *duration)
			defer stop()
			go func() {
				select {
				case <-durationCtx.Done():
					cancel()
				case <-ctx.Done():
				}
			}()
		}
		manifest := map[string]any{
			"schema_version":                   1,
			"layout_version":                   3,
			"capture_mode":                     "raw",
			"capture_ports":                    portNumbers(capturePorts),
			"local_addresses":                  captureAddresses(),
			"hostname":                         host,
			"os":                               runtime.GOOS,
			"arch":                             runtime.GOARCH,
			"name":                             *name,
			"mode":                             cmd,
			"started":                          s.stats.Started,
			"filter":                           filter,
			"interfaces":                       names,
			"network_namespace_pid":            networkNamespacePID,
			"service":                          *service,
			"targets":                          discoverTargets("/proc", *service, *pid, *lib),
			"tls_enabled":                      cmd == "capture" && !*noTLS,
			"detection_mode":                   "offline",
			"trusted_proxies":                  trustedProxies,
			"openssl_preload_socket":           *preloadSocket,
			"openssl_preload_allow_uid":        preloadUIDs,
			"tls_coverage":                     "unverified",
			"tls_missing_estimate":             nil,
			"header_limit":                     32768,
			"unsupported_content":              []string{"HTTP/3", "WebSocket payload", "Go TLS", "generic JSSE"},
			"preflight":                        checks,
			"collector_memory_mib":             collectorMemoryMiB,
			"pcap_buffer_mib":                  pcapBufferMiB,
			"collector_cpu_percent":            collectorCPUPercent,
			"probe_drain_timeout_ms":           drainTimeout.Milliseconds(),
			"stop_timeout_ms":                  stopTimeout.Milliseconds(),
			"evidence_backpressure":            string(backpressurePolicy),
			"in_process_probe_budget_included": false,
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
			s.mu.Lock()
			fatal := s.fatal
			s.mu.Unlock()
			if e == nil {
				e = fatal
			}
			if e != nil {
				return e
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := checkDisk(s); err != nil {
				return err
			}
			s.mu.Lock()
			s.stats.State = "complete"
			s.mu.Unlock()
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
					if err := capturePreload(ctx, s, p, *preloadSocket, preloadUIDs); err != nil {
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
		stopRequestedAt := time.Now().UTC()
		stopReason := "signal_or_duration"
		if durationCtx != nil && errors.Is(durationCtx.Err(), context.DeadlineExceeded) {
			stopReason = "duration"
		} else if sigCtx.Err() != nil {
			stopReason = "signal"
		}
		s.mu.Lock()
		s.stats.Stopped = stopRequestedAt
		s.stats.DrainState = "draining"
		s.mu.Unlock()
		s.report()
		cancel()
		recorderFinalized = true // No unbounded second close in the deferred cleanup.
		budgetExceeded, closeErr := shutdownWithin(wg.Wait, p.close, stopTimeout)
		if closeErr != nil {
			s.fail(closeErr)
		}
		if budgetExceeded {
			s.gap("collector", "", "stop_budget_exceeded", "shutdowns", 1)
			s.fail(fmt.Errorf("shutdown exceeded --stop-timeout %s; remaining probe data not confirmed", stopTimeout))
		}
		fatal := finishCaptureStateReason(s, *noTLS, *requirePlaintext, budgetExceeded, stopReason)
		s.report()
		emit(snapshotStats(s))
		return fatal
	}
	return fmt.Errorf("unknown command %s", cmd)
}

// finishCaptureState reads the final error only after plaintext checks, which
// may themselves fail the capture. Callers use the same outcome for JSON and
// the process exit status.
func finishCaptureState(s *Store, noTLS, requirePlaintext, budgetExceeded bool) error {
	return finishCaptureStateReason(s, noTLS, requirePlaintext, budgetExceeded, "signal_or_duration")
}

func finishCaptureStateReason(s *Store, noTLS, requirePlaintext, budgetExceeded bool, stopReason string) error {
	s.mu.Lock()
	s.syncAtomicStatsLocked()
	if s.stats.Stopped.IsZero() {
		s.stats.Stopped = time.Now().UTC()
	}
	s.stats.DrainState = "unverified"
	if noTLS || (s.stats.TLS == "http-only" && len(s.stats.ProbeExits) == 0) {
		s.stats.DrainState = "confirmed"
	} else if len(s.stats.ProbeExits) > 0 {
		confirmed := true
		for _, exit := range s.stats.ProbeExits {
			confirmed = confirmed && exit.DataDrained && (!exit.HookBased || exit.HooksRemoved)
		}
		if confirmed {
			s.stats.DrainState = "confirmed"
		}
	}
	finishIISObservability(s, requirePlaintext)
	if stopReason == "" {
		stopReason = "signal_or_duration"
	}
	s.stats.StopReason = stopReason
	s.stats.State = "stopped"
	if s.stats.RawEvidenceWriters > 0 || s.stats.RawEvidencePendingBytes > 0 || s.stats.RawEvidenceDrainUnconfirmed || hasUnconfirmedDrainGap(s.stats.GapCounts) {
		s.stats.DrainState = "unverified"
	}
	if budgetExceeded {
		s.stats.StopReason = "stop_budget_exceeded"
		s.stats.DrainState = "unverified"
	}
	fatal := s.fatal
	if fatal != nil {
		s.stats.State = "failed"
		if !budgetExceeded {
			s.stats.StopReason = "fatal_error"
		}
		s.stats.DrainState = "unverified"
	}
	s.stats.IntegrityWarnings = session.ComputeIntegrityWarnings(s.stats, nil, s.stats.Stopped)
	s.mu.Unlock()
	return fatal
}

func hasUnconfirmedDrainGap(gaps map[string]uint64) bool {
	for key, count := range gaps {
		if count == 0 {
			continue
		}
		if strings.Contains(key, "/drain_unconfirmed/") || strings.Contains(key, "/drain_sequence_mismatch/") || strings.Contains(key, "/drain_timeout/") {
			return true
		}
	}
	return false
}

// shutdownWithin shares one deadline between workers and recorder. A blocked
// close is never invoked a second time on return, and background goroutines do
// not read mutable timeout flags or modify the caller's error result.
func shutdownWithin(wait func(), closeRecorder func() error, budget time.Duration) (bool, error) {
	deadline := time.Now().Add(budget)
	workersStopped := waitWithin(wait, budget)
	closed := make(chan error, 1)
	go func() { closed <- closeRecorder() }()
	if !workersStopped {
		return true, nil
	}
	timer := time.NewTimer(max(0, time.Until(deadline)))
	defer timer.Stop()
	select {
	case err := <-closed:
		return false, err
	case <-timer.C:
		return true, nil
	}
}

// Workers may still finish after a shutdown timeout. Never emit references to
// their live maps and slices after releasing the store lock.
func snapshotStats(s *Store) Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncAtomicStatsLocked()
	b, _ := json.Marshal(s.stats)
	var snapshot Stats
	_ = json.Unmarshal(b, &snapshot)
	return snapshot
}

// waitWithin runs fn and reports whether it returned within budget. On
// timeout fn keeps running in the background; the process is about to exit.
func waitWithin(fn func(), budget time.Duration) bool {
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func maintain(s *Store) error {
	return checkDisk(s)
}

func checkDisk(s *Store) error {
	var total int64
	err := filepath.Walk(s.dir, func(path string, i os.FileInfo, e error) error {
		// Scope and status are atomically replaced while this walk is in flight.
		if path != s.dir && errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			if os.IsNotExist(e) {
				return nil
			}
			return e
		}
		if !i.IsDir() {
			total += i.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
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
