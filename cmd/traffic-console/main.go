package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Sunmedalia/traffic/internal/replay"
	"github.com/Sunmedalia/traffic/internal/session"
)

func emit(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}
func main() {
	if err := session.InitRuntime(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	session.PrivateUmask()
	if len(args) > 0 && args[0] == "help" {
		if len(args) == 1 || strings.HasPrefix(args[1], "-") {
			printConsoleHelp(os.Stdout, "", consoleHelpFlag(args, "cn-help"), nil)
			return nil
		}
		args = append(append([]string{args[1]}, args[2:]...), "--help")
	}
	globalHelp := len(args) > 0 && strings.HasPrefix(args[0], "-")
	cnHelp := consoleHelpFlag(args, "cn-help")
	cmd := "view"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "view", "web", "status", "requests", "events", "show", "export", "analyze", "rules":
	default:
		return fmt.Errorf("unknown analysis command %q; use traffic for collection", cmd)
	}
	if cmd == "rules" {
		if cnHelp || consoleHelpFlag(args, "help") || consoleHelpFlag(args, "h") {
			printConsoleHelp(os.Stdout, "rules", cnHelp, nil)
			return nil
		}
		if len(args) != 2 || args[0] != "check" {
			return errors.New("usage: traffic-console rules check FILE")
		}
		if err := loadRules(args[1]); err != nil {
			return err
		}
		emit(map[string]any{"valid": true, "rules": len(rules)})
		return nil
	}
	id := ""
	if (cmd == "show" || cmd == "export") && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("traffic-console "+cmd, flag.ContinueOnError)
	fs.Usage = func() {
		helpCmd := cmd
		if globalHelp {
			helpCmd = ""
		}
		printConsoleHelp(fs.Output(), helpCmd, cnHelp, fs)
	}
	cnRequested := fs.Bool("cn-help", false, "show Chinese command help")
	ruleFile := fs.String("rules", "", "additional YAML rules for analyze")
	scanDuration := fs.Duration("scan-window", time.Minute, "scan correlation window for analyze")
	scanPaths := fs.Int("scan-paths", 20, "distinct paths for scan detection in analyze")
	webhookURL := fs.String("alert-webhook", "", "send local analysis alerts; TRAFFIC_WEBHOOK_TOKEN requires HTTPS outside loopback")
	privateWebhook := fs.Bool("allow-private-webhook", false, "allow RFC1918 and IPv6 ULA webhook destinations; link-local and metadata addresses remain blocked")
	requestBytes := fs.Int("request-limit", 1<<20, "maximum locally reconstructed request body bytes (up to 16 MiB)")
	responseBytes := fs.Int("response-limit", 1<<20, "maximum locally reconstructed response body bytes (up to 16 MiB)")
	dir := fs.String("session", "", "existing session directory")
	dataDir := fs.String("data-dir", "", "session browser search directory")
	rulesDir := fs.String("rules-dir", defaultRulesDir(), "managed YAML rule directory for web")
	refresh := fs.Duration("refresh", time.Second, "TUI or web refresh interval")
	listen := fs.String("listen", "127.0.0.1:8080", "web listen address")
	allowRemote := fs.Bool("allow-remote", false, "allow web to listen on a non-loopback address over plain HTTP")
	out := fs.String("out", "", "export archive (must not exist)")
	limit := fs.Int("limit", 100, "maximum query results")
	service := fs.String("service", "", "service filter")
	client := fs.String("client", "", "source address filter")
	rule := fs.String("rule", "", "rule ID filter")
	severity := fs.String("severity", "", "minimum severity: low, medium, high")
	since := fs.String("since", "", "RFC3339 start time")
	fs.Bool("json", false, "JSON output for query commands (default)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *cnRequested {
		fs.Usage()
		return nil
	}
	if cmd != "analyze" {
		var invalid string
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "rules", "scan-window", "scan-paths", "alert-webhook", "allow-private-webhook", "request-limit", "response-limit":
				invalid = f.Name
			}
		})
		if invalid != "" {
			return fmt.Errorf("--%s requires traffic-console analyze", invalid)
		}
	} else {
		var invalid string
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "session", "rules", "scan-window", "scan-paths", "alert-webhook", "allow-private-webhook", "json", "request-limit", "response-limit":
			default:
				invalid = f.Name
			}
		})
		if invalid != "" {
			return fmt.Errorf("--%s is not an analyze option", invalid)
		}
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if cmd != "web" && cmd != "view" {
		var used bool
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "rules-dir" {
				used = true
			}
		})
		if used {
			return errors.New("--rules-dir requires traffic-console web or view")
		}
	}
	if *limit < 1 {
		return errors.New("--limit must be positive")
	}
	if (cmd == "show" || cmd == "export") && id == "" {
		return errors.New("transaction ID required")
	}
	if *severity != "" && *severity != "low" && *severity != "medium" && *severity != "high" {
		return errors.New("--severity must be low, medium, or high")
	}
	if *since != "" {
		stamp, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("--since: %w", err)
		}
		*since = stamp.UTC().Format(indexTimeFormat)
	}
	if cmd == "web" {
		return runWeb(*dir, *dataDir, *rulesDir, *listen, *allowRemote, *refresh)
	}
	if cmd == "view" {
		return runSessionBrowser(*dir, *dataDir, *rulesDir, *refresh, tuiFilter{Client: *client, Rule: *rule, Severity: *severity, Since: *since, Service: *service})
	}
	if *dir == "" {
		return errors.New("--session required")
	}
	if cmd == "analyze" {
		if *requestBytes < 1 || *responseBytes < 1 || *requestBytes > 16<<20 || *responseBytes > 16<<20 {
			return errors.New("local body limits must be between 1 byte and 16 MiB")
		}
		if *scanDuration <= 0 || *scanPaths < 1 {
			return errors.New("invalid scan detection limits")
		}
		if err := validateWebhook(*webhookURL); err != nil {
			return err
		}
		scanWindow, scanThreshold = *scanDuration, *scanPaths
		if err := loadRules(*ruleFile); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if *privateWebhook && *webhookURL != "" {
			privateWebhookEndpoint.Store(webhookURL)
			defer privateWebhookEndpoint.CompareAndSwap(webhookURL, nil)
		}
		report, err := analyzeConfigured(ctx, *dir, *webhookURL, rules, *scanDuration, *scanPaths, replay.Options{RequestLimit: *requestBytes, ResponseLimit: *responseBytes})
		if err != nil {
			return err
		}
		for _, w := range report.IntegrityWarnings {
			fmt.Fprintf(os.Stderr, "⚠ 完整性告警：%s\n", w)
		}
		if skipped := report.ScanSkipped; skipped != nil {
			fmt.Fprintf(os.Stderr, "⚠ 扫描检测达到跟踪上限：%d 条事务因客户端超过 %d 个、%d 条因单个客户端路径超过 %d 条未参与 SCAN-001 统计，其中的扫描可能未报出\n", skipped.Clients, maxScanClients, skipped.Paths, maxScanPaths)
		}
		emit(report)
		return nil
	}
	if cmd == "status" {
		b, e := os.ReadFile(filepath.Join(*dir, "status.json"))
		if e != nil {
			return e
		}
		var status map[string]any
		if json.Unmarshal(b, &status) == nil {
			var reconstructed *Stats
			if report, err := readAnalysisReport(*dir); err == nil {
				status["analysis"] = report
				reconstructed = report.Reconstruction
			}
			if warnings := sessionIntegrityWarnings(*dir, reconstructed); len(warnings) > 0 {
				status["integrity_warnings"] = warnings
			}
			if info, e := os.Stat(filepath.Join(*dir, "status.json")); e == nil && time.Since(info.ModTime()) > 5*time.Second && status["state"] == "running" {
				checked, note := readTUIStatus(*dir)
				status["state"] = checked.State
				status["note"] = note
			}
			emit(status)
		} else {
			return fmt.Errorf("invalid status JSON")
		}
		return nil
	}
	s, e := openStore(*dir)
	if e != nil {
		return e
	}
	defer s.db.Close()
	if s.analysisNote != "" {
		fmt.Fprintln(os.Stderr, s.analysisNote)
	}
	if cmd == "show" || cmd == "export" {
		var b []byte
		if e = s.db.QueryRow("SELECT data FROM records WHERE id=?", id).Scan(&b); e != nil {
			return e
		}
		var t Transaction
		if e = json.Unmarshal(b, &t); e != nil {
			return e
		}
		if cmd == "show" {
			decoded, decodedView := session.DecodedBody(t.Request, 1<<20)
			emit(map[string]any{"transaction": t, "request_text": session.SafeText(t.Request), "response_text": session.SafeText(t.Response), "decoded_body": decoded, "decoded_view": decodedView})
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
	query := "SELECT data FROM records WHERE time>=? AND (?='' OR client=? OR client LIKE ?)"
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
		if *service != "" && t.Service != *service {
			continue
		}
		if cmd == "events" && len(t.Alerts) == 0 {
			continue
		}
		if *rule != "" || *severity != "" {
			match := false
			for _, a := range t.Alerts {
				if (*rule == "" || a.Rule == *rule) && severityRank(a.Severity) >= severityRank(*severity) {
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
