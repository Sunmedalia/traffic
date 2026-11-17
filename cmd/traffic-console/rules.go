package main

import (
	"bufio"
	"bytes"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

type Rule struct {
	ID               string `yaml:"id" json:"id"`
	Version          int    `yaml:"version" json:"version"`
	Severity         string `yaml:"severity" json:"severity"`
	Field            string `yaml:"field" json:"field"`
	Pattern          string `yaml:"pattern" json:"pattern"`
	rx               *regexp.Regexp
	requiredLiterals [][]string
}

var builtinRules = []Rule{
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

var rules = append([]Rule(nil), builtinRules...)
var requestLimit = 1 << 20
var responseLimit = 1 << 20
var scanWindow = time.Minute
var scanThreshold = 20

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
		expression, parseErr := syntax.Parse(r.Pattern, syntax.Perl)
		if parseErr != nil {
			return parseErr
		}
		r.requiredLiterals = necessaryRuleLiterals(expression)
	}
	return nil
}
func rulesFromYAML(data []byte) ([]Rule, error) {
	rs := append([]Rule(nil), builtinRules...)
	if len(data) > 0 {
		var extra []Rule
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&extra); err != nil {
			return nil, err
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, fmt.Errorf("rule file must contain exactly one YAML document")
		}
		if len(extra) == 0 {
			return nil, fmt.Errorf("rule file must contain a non-empty rule list")
		}
		rs = append(rs, extra...)
	}
	if err := compileRules(rs); err != nil {
		return nil, err
	}
	return rs, nil
}
func loadRules(path string) error {
	var data []byte
	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return fmt.Errorf("empty rule file")
		}
	}
	rs, err := rulesFromYAML(data)
	if err == nil {
		rules = rs
	}
	return err
}

func detect(t Transaction) []Alert { return detectWithRules(t, rules) }

func detectWithRules(t Transaction, rs []Rule) []Alert {
	return detectWithLimits(t, rs, requestLimit, responseLimit)
}

func detectWithLimits(t Transaction, rs []Rule, requestLimit, responseLimit int) []Alert {
	var out []Alert
	var request, response *detectionHTTP
	type fieldView struct{ field, view string }
	views := map[fieldView][]decodedView{}
	match := func(rule Rule, text, view string) *Alert {
		key := fieldView{rule.Field, view}
		variants, ok := views[key]
		if !ok {
			variants = decodeViews(text)
			views[key] = variants
		}
		return matchDecodedViews(rule, variants, view)
	}
	for _, rule := range rs {
		responseRule := strings.HasPrefix(rule.Field, "response")
		var message *detectionHTTP
		if rule.Field != "url" {
			if responseRule {
				if response == nil {
					m := detectionMessage(t.Response, true, responseLimit)
					response = &m
				}
				message = response
			} else {
				if request == nil {
					m := detectionMessage(t.Request, false, requestLimit)
					request = &m
				}
				message = request
			}
		}
		text, view := t.URL, "url"
		if message != nil {
			text, view = message.content(rule.Field)
		}
		alert := match(rule, text, view)
		if alert == nil && message != nil && (rule.Field == "request" || rule.Field == "response" || rule.Field == "request.body" || rule.Field == "response.body") && message.decoded != "" {
			alert = match(rule, message.decoded, message.decodedView)
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
	reader := bufio.NewReaderSize(bytes.NewReader(raw), 4096)
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

type decodedView struct {
	text   string
	round  int
	folded string
	ascii  bool
}

func decodeViews(text string) []decodedView {
	folded, ascii := foldedASCII(text)
	variants := []decodedView{{text: text, round: 0, folded: folded, ascii: ascii}}
	for round := 1; round <= 2; round++ {
		decoded := decodePercent(text)
		if decoded == text {
			break
		}
		folded, ascii := foldedASCII(decoded)
		variants = append(variants, decodedView{text: decoded, round: round, folded: folded, ascii: ascii})
		text = decoded
	}
	return variants
}
func matchDecodedViews(rule Rule, variants []decodedView, view string) *Alert {
	for _, variant := range variants {
		if !rule.mayMatch(variant) {
			continue
		}
		if match := rule.rx.FindString(variant.text); match != "" {
			return &Alert{Rule: rule.ID, Version: rule.Version, Severity: rule.Severity, Field: rule.Field, Match: match, Decoding: variant.round, View: view}
		}
	}
	return nil
}
func matchView(rule Rule, text, view string) *Alert {
	return matchDecodedViews(rule, decodeViews(text), view)
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

type scanPath struct {
	when   time.Time
	status int
}
type scanState struct {
	paths     map[string]scanPath
	lastAlert time.Time
}

type scanTracker struct {
	sync.Mutex
	clients map[string]*scanState
}

var scans = scanTracker{clients: map[string]*scanState{}}

func scan(t Transaction) *Alert { return scanWithState(t, &scans, scanWindow, scanThreshold) }

func scanWithState(t Transaction, scans *scanTracker, scanWindow time.Duration, scanThreshold int) *Alert {
	if t.Status == 0 {
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
