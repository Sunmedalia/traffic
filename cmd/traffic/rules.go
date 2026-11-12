package main

import (
	"bufio"
	"bytes"
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

	"github.com/Sunmedalia/traffic/internal/session"
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
	{ID: "XSS-001", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)(<\s*script\b|<[^>]+\bon[a-z]+\s*=|javascript\s*:)`},
	{ID: "SSRF-001", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)(https?://(localhost|127\.[0-9.]+|\[::1\]|169\.254\.169\.254|metadata\.google\.internal)([:/\s?]|$)|\b(gopher|dict|file)://)`},
	{ID: "XXE-001", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)<!ENTITY\s+[^>]+\b(SYSTEM|PUBLIC)\s+`},
	{ID: "SSTI-001", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)(\{\{[^}]{0,200}(__class__|__globals__|config\b|[0-9]+\s*\*\s*[0-9]+)|\$\{[^}]{0,200}(Runtime|ProcessBuilder|[0-9]+\s*\*\s*[0-9]+)|<%=?[^%]{0,200}(Runtime|system|exec)\b)`},
	{ID: "JNDI-001", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)\$\{\s*jndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|http)\s*:`},
	{ID: "DESERIAL-001", Version: 1, Severity: "high", Field: "request.body", Pattern: `(?i)(rO0AB|<java\b[^>]*\bclass=["']java\.beans\.XMLDecoder|O:[0-9]+:"[^"\r\n]+":[0-9]+:\{)`},
	{ID: "WEBSHELL-UPLOAD-001", Version: 1, Severity: "high", Field: "request.body", Pattern: `(?i)(filename\s*=\s*"?[^"\r\n;]*\.(php[0-9]?|phtml|jsp[x]?|asp[x]?)([";\s]|$)|<\?php[^\r\n]{0,300}\b(eval|assert|system|passthru|shell_exec)\s*\()`},
	{ID: "WEBSHELL-ACCESS-001", Version: 1, Severity: "medium", Field: "url", Pattern: `(?i)/(shell|webshell|cmd|c99|r57|antsword|behinder)\.(php[0-9]?|phtml|jsp[x]?|asp[x]?)([?/#]|$)`},
	{ID: "RESPONSE-PASSWD-001", Version: 1, Severity: "high", Field: "response.body", Pattern: `\broot:[^:\r\n]*:0:0:`},
	{ID: "RESPONSE-CMD-001", Version: 1, Severity: "high", Field: "response.body", Pattern: `\buid=[0-9]+\([^)]*\)\s+gid=[0-9]+\(`},
}

func compileRules(rs []Rule) error {
	seen := map[string]bool{}
	for i := range rs {
		r := &rs[i]
		if r.ID == "" || seen[r.ID] || r.Version < 1 {
			return fmt.Errorf("invalid or duplicate rule %q", r.ID)
		}
		seen[r.ID] = true
		if !validRuleField(r.Field) {
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
	request := detectionMessage(t.Request, false, requestLimit)
	response := detectionMessage(t.Response, true, responseLimit)
	for _, rule := range rules {
		message := request
		if strings.HasPrefix(rule.Field, "response") {
			message = response
		}
		text, view := message.content(rule.Field)
		if rule.Field == "url" {
			text, view = t.URL, "url"
		}
		alert := matchView(rule, text, view)
		if alert == nil && (rule.Field == "request" || rule.Field == "response" || rule.Field == "request.body" || rule.Field == "response.body") && message.decoded != "" {
			alert = matchView(rule, message.decoded, message.decodedView)
		}
		if alert != nil {
			out = append(out, *alert)
		}
	}
	return out
}

// Header selectors use an HTTP field name, for example request.header.User-Agent.
func validRuleField(field string) bool {
	for _, side := range []string{"request", "response"} {
		if field == side || field == side+".headers" || field == side+".body" {
			return true
		}
		if name, ok := strings.CutPrefix(field, side+".header."); ok {
			if name == "" {
				return false
			}
			for _, c := range name {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
					return false
				}
			}
			return true
		}
	}
	return field == "url"
}

type detectionHTTP struct {
	raw, headers, body, decoded, decodedView string
	fields                                   http.Header
}

func detectionMessage(raw []byte, response bool, limit int) detectionHTTP {
	message := detectionHTTP{raw: string(raw)}
	// Keep bounded partial bodies searchable even when the saved message is truncated.
	head, payload, found := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !found {
		head, payload, found = bytes.Cut(raw, []byte("\n\n"))
	}
	if found {
		_, headers, _ := bytes.Cut(head, []byte("\n"))
		message.headers, message.body = string(headers), string(payload)
	}
	reader := bufio.NewReader(bytes.NewReader(raw))
	var body io.ReadCloser
	if response {
		parsed, err := http.ReadResponse(reader, nil)
		if err == nil {
			message.fields, body = parsed.Header, parsed.Body
		}
	} else {
		parsed, err := http.ReadRequest(reader)
		if err == nil {
			message.fields, body = parsed.Header, parsed.Body
			if parsed.Host != "" {
				message.fields.Set("Host", parsed.Host)
			}
		}
	}
	if body != nil {
		data, _ := io.ReadAll(io.LimitReader(body, int64(limit)))
		body.Close()
		message.body = string(data)
	}
	message.decoded, message.decodedView = session.DecodedBody(raw, limit)
	return message
}

func (m detectionHTTP) content(field string) (string, string) {
	if _, name, ok := strings.Cut(field, ".header."); ok {
		return strings.Join(m.fields.Values(name), "\n"), field
	}
	if strings.HasSuffix(field, ".headers") {
		return m.headers, field
	}
	if strings.HasSuffix(field, ".body") {
		return m.body, field
	}
	return m.raw, field
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

func decodedBody(raw []byte) (string, string) { return session.DecodedBody(raw, requestLimit) }

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
