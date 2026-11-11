package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID       string `yaml:"id"`
	Version  int    `yaml:"version"`
	Severity string `yaml:"severity"`
	Field    string `yaml:"field"`
	Pattern  string `yaml:"pattern"`
	rx       *regexp.Regexp
}

var rules = []Rule{
	{ID: "SQLI-001", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)(union\s+(all\s+)?select\b|\bor\s+['"]?\d+['"]?\s*=\s*['"]?\d+|\b(sleep|benchmark)\s*\()`},
	{ID: "CMD-001", Version: 1, Severity: "high", Field: "request", Pattern: "(?i)([;|&]\\s*(id|whoami|cat|curl|wget|bash|sh)\\b|\\$\\([^)]*\\)|`[^`]+`)"},
	{ID: "PATH-001", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)(\.\.[/\\]){2,}`},
	{ID: "FILE-001", Version: 1, Severity: "medium", Field: "url", Pattern: `(?i)(/\.env([?/#]|$)|/\.git/|/wp-config\.php|/etc/passwd|/WEB-INF/web\.xml)`},
}

func compileRules(rs []Rule) error {
	seen := map[string]bool{}
	for i := range rs {
		r := &rs[i]
		if r.ID == "" || seen[r.ID] || r.Version < 1 {
			return fmt.Errorf("invalid or duplicate rule %q", r.ID)
		}
		seen[r.ID] = true
		if r.Field != "url" && r.Field != "request" {
			return fmt.Errorf("unsupported field %s", r.Field)
		}
		if r.Severity != "low" && r.Severity != "medium" && r.Severity != "high" {
			return fmt.Errorf("invalid severity")
		}
		rx, e := regexp.Compile(r.Pattern)
		if e != nil {
			return e
		}
		r.rx = rx
	}
	return nil
}
func loadRules(path string) error {
	if path != "" {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var extra []Rule
		decoder := yaml.NewDecoder(bytes.NewReader(b))
		decoder.KnownFields(true)
		if e = decoder.Decode(&extra); e != nil {
			return e
		}
		rules = append(rules, extra...)
	}
	return compileRules(rules)
}

var noDetect bool

func detect(t Transaction) []Alert {
	if noDetect {
		return nil
	}
	var out []Alert
	decoded, decodedView := decodedBody(t.Request)
	for _, rule := range rules {
		text := string(t.Request)
		view := "request"
		if rule.Field == "url" {
			text = t.URL
			view = "url"
		}
		alert := matchView(rule, text, view)
		if alert == nil && rule.Field == "request" && decoded != "" {
			alert = matchView(rule, decoded, decodedView)
		}
		if alert != nil {
			out = append(out, *alert)
		}
	}
	return out
}
func matchView(rule Rule, text, view string) *Alert {
	for round := 0; round <= 2; round++ {
		if match := rule.rx.FindString(text); match != "" {
			return &Alert{Rule: rule.ID, Version: rule.Version, Severity: rule.Severity, Field: rule.Field, Match: match, Decoding: round, View: view}
		}
		decoded := decodePercent(text)
		if decoded == text {
			break
		}
		text = decoded
	}
	return nil
}

var validPercentEscape = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

func decodePercent(text string) string {
	decoded, err := url.QueryUnescape(text)
	if err == nil {
		return decoded
	}
	return validPercentEscape.ReplaceAllStringFunc(strings.ReplaceAll(text, "+", " "), func(escape string) string {
		value, _ := strconv.ParseUint(escape[1:], 16, 8)
		return string([]byte{byte(value)})
	})
}

func safeText(b []byte) string { return strings.ToValidUTF8(string(b), "�") }

func decodedBody(raw []byte) (string, string) {
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return "", ""
	}
	defer request.Body.Close()
	if !strings.EqualFold(request.Header.Get("Content-Encoding"), "gzip") {
		return "", ""
	}
	reader, err := gzip.NewReader(request.Body)
	if err != nil {
		return "", ""
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, int64(requestLimit)+1))
	view := "gzip-body"
	if len(body) > requestLimit {
		body = body[:requestLimit]
		view = "gzip-body-truncated"
	} else if err != nil {
		view = "gzip-body-incomplete"
	}
	return string(body), view
}

type scanPath struct {
	when   time.Time
	status int
}
type scanState struct {
	paths     map[string]scanPath
	lastAlert time.Time
}

var scans = struct {
	sync.Mutex
	clients map[string]*scanState
}{clients: map[string]*scanState{}}

func scan(t Transaction) *Alert {
	if noDetect || t.Status == 0 {
		return nil
	}
	host, _, e := net.SplitHostPort(t.Client)
	if e != nil || host == "unknown" {
		return nil
	}
	scans.Lock()
	defer scans.Unlock()
	now := t.Time
	for ip, s := range scans.clients {
		for path, x := range s.paths {
			if now.Sub(x.when) > scanWindow {
				delete(s.paths, path)
			}
		}
		if len(s.paths) == 0 {
			delete(scans.clients, ip)
		}
	}
	s := scans.clients[host]
	if s == nil {
		if len(scans.clients) >= 2000 {
			return nil
		}
		s = &scanState{paths: map[string]scanPath{}}
		scans.clients[host] = s
	}
	path := strings.SplitN(t.URL, "?", 2)[0]
	if len(s.paths) >= 1000 {
		return nil
	}
	s.paths[path] = scanPath{now, t.Status}
	missing := 0
	for _, x := range s.paths {
		if x.status == 404 {
			missing++
		}
	}
	if len(s.paths) >= scanThreshold && missing*2 >= len(s.paths) && now.Sub(s.lastAlert) >= scanWindow {
		s.lastAlert = now
		return &Alert{Rule: "SCAN-001", Version: 1, Severity: "medium", Field: "path-window", Match: fmt.Sprintf("%d distinct paths, %d HTTP 404 within %s", len(s.paths), missing, scanWindow)}
	}
	return nil
}
