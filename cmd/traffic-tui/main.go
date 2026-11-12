package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	session.PrivateUmask()
	cmd := "view"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "view", "status", "requests", "events", "show", "export":
	default:
		return fmt.Errorf("unknown analysis command %q; use traffic for collection", cmd)
	}
	id := ""
	if (cmd == "show" || cmd == "export") && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("traffic-tui "+cmd, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "traffic-tui [--data-dir ROOT | --session DIR]\ntraffic-tui <status|requests|events|show ID|export ID> --session DIR")
		fmt.Fprintln(fs.Output(), "默认打开中文会话选择界面，查询命令输出 JSON。")
		fs.PrintDefaults()
	}
	dir := fs.String("session", "", "existing session directory")
	dataDir := fs.String("data-dir", "", "session browser search directory")
	refresh := fs.Duration("refresh", time.Second, "TUI refresh interval")
	out := fs.String("out", "", "export archive (must not exist)")
	limit := fs.Int("limit", 100, "maximum query results")
	service := fs.String("service", "", "service filter")
	client := fs.String("client", "", "source address filter")
	rule := fs.String("rule", "", "rule ID filter")
	severity := fs.String("severity", "", "severity filter: low, medium, high")
	since := fs.String("since", "", "RFC3339 start time")
	fs.Bool("json", false, "JSON output for query commands (default)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
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
	if cmd == "view" {
		return runSessionBrowser(*dir, *dataDir, *refresh, tuiFilter{Client: *client, Rule: *rule, Severity: *severity, Since: *since, Service: *service})
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
	s, e := openStore(*dir)
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
		if *service != "" && t.Service != *service {
			continue
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
