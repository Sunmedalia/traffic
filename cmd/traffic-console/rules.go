package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/heap"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

type Rule struct {
	ID        string `yaml:"id" json:"id"`
	Version   int    `yaml:"version" json:"version"`
	Severity  string `yaml:"severity" json:"severity"`
	Field     string `yaml:"field" json:"field"`
	Pattern   string `yaml:"pattern" json:"pattern"`
	rx        *regexp.Regexp
	prefilter *prefilter
}

var builtinRules = []Rule{
	{ID: "SQLI-001", Version: 1, Severity: "high", Field: "request", Pattern: `(?i)(union\s+(all\s+)?select\b|\bor\s+['"]?\d+['"]?\s*=\s*['"]?\d+|\b(sleep|benchmark)\s*\()`},
	// A command after a separator must be followed by a space, the end or a
	// shell metacharacter, so parameters named like commands (&id=5, &cat=3)
	// are not taken for command injection.
	{ID: "CMD-001", Version: 2, Severity: "high", Field: "request", Pattern: "(?i)([;|&]\\s*(id|whoami|cat|curl|wget|bash|sh)(\\s|$|[;|&<>`$)'\"])|\\$\\([^)]*\\)|`[^`]+`)"},
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

const (
	maxCompiledRules     = 512
	maxRulePatternLength = 4096
)

func compileRules(rs []Rule) error {
	if len(rs) > maxCompiledRules {
		return fmt.Errorf("too many rules: %d exceeds limit %d", len(rs), maxCompiledRules)
	}
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
		if len(r.Pattern) > maxRulePatternLength {
			return fmt.Errorf("rule %q pattern too long (%d bytes, max %d)", r.ID, len(r.Pattern), maxRulePatternLength)
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
		r.prefilter = rulePrefilter(expression)
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

type messageNeeds struct {
	raw     bool
	headers bool
	fields  bool
	body    bool
	decoded bool
}

var allMessageNeeds = messageNeeds{raw: true, headers: true, fields: true, body: true, decoded: true}

type ruleFieldPlan struct {
	request  messageNeeds
	response messageNeeds
}

func planRuleFields(rs []Rule) ruleFieldPlan {
	var plan ruleFieldPlan
	for _, r := range rs {
		var dst *messageNeeds
		switch {
		case r.Field == "url":
			continue
		case strings.HasPrefix(r.Field, "response"):
			dst = &plan.response
		default:
			dst = &plan.request
		}
		switch {
		case r.Field == "request" || r.Field == "response":
			dst.raw = true
			dst.decoded = true
		case strings.Contains(r.Field, ".header."):
			dst.fields = true
		case r.Field == "request.headers" || r.Field == "response.headers":
			dst.headers = true
		case r.Field == "request.body" || r.Field == "response.body":
			dst.body = true
			dst.decoded = true
		}
	}
	return plan
}

func detect(t Transaction) []Alert { return detectWithRules(t, rules) }

func detectWithRules(t Transaction, rs []Rule) []Alert {
	return detectWithLimits(t, rs, requestLimit, responseLimit)
}

func detectWithLimits(t Transaction, rs []Rule, requestLimit, responseLimit int) []Alert {
	return detectWithPlan(t, rs, planRuleFields(rs), requestLimit, responseLimit, nil)
}

func detectWithPlan(t Transaction, rs []Rule, plan ruleFieldPlan, requestLimit, responseLimit int, br *bufio.Reader) []Alert {
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
					m := detectionMessageWith(t.Response, true, responseLimit, plan.response, br)
					response = &m
				}
				message = response
			} else {
				if request == nil {
					m := detectionMessageWith(t.Request, false, requestLimit, plan.request, br)
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

var gzipReaderPool sync.Pool

func gunzipBody(src io.Reader, limit int) (string, string) {
	var reader *gzip.Reader
	var err error
	if pooled := gzipReaderPool.Get(); pooled != nil {
		reader = pooled.(*gzip.Reader)
		err = reader.Reset(src)
		if err != nil {
			gzipReaderPool.Put(reader)
			return "", ""
		}
	} else {
		reader, err = gzip.NewReader(src)
		if err != nil {
			return "", ""
		}
	}
	defer func() {
		_ = reader.Close()
		gzipReaderPool.Put(reader)
	}()
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	view := "gzip-body"
	if len(decoded) > limit {
		decoded = decoded[:limit]
		view = "gzip-body-truncated"
	} else if err != nil {
		view = "gzip-body-incomplete"
	}
	return string(decoded), view
}

func detectionMessage(raw []byte, response bool, limit int) detectionHTTP {
	return detectionMessageWith(raw, response, limit, allMessageNeeds, nil)
}

func detectionMessageWith(raw []byte, response bool, limit int, needs messageNeeds, br *bufio.Reader) detectionHTTP {
	if len(raw) == 0 {
		return detectionHTTP{}
	}
	var message detectionHTTP
	if needs.raw {
		message.raw = string(raw)
	}
	var head, payload []byte
	var found bool
	if needs.headers || needs.body {
		// Keep bounded partial bodies searchable even when the saved message is truncated.
		head, payload, found = bytes.Cut(raw, []byte("\r\n\r\n"))
		if !found {
			head, payload, found = bytes.Cut(raw, []byte("\n\n"))
		}
		if found && needs.headers {
			_, headers, _ := bytes.Cut(head, []byte("\n"))
			message.headers = string(headers)
		}
	}
	if !needs.fields && !needs.body && !needs.decoded {
		return message
	}
	var reader *bufio.Reader
	if br != nil {
		br.Reset(bytes.NewReader(raw))
		reader = br
	} else {
		reader = bufio.NewReaderSize(bytes.NewReader(raw), 4096)
	}
	var parsedHeader http.Header
	var body io.ReadCloser
	if response {
		parsed, err := http.ReadResponse(reader, nil)
		if err == nil {
			parsedHeader, body = parsed.Header, parsed.Body
		}
	} else {
		parsed, _, err := session.ReadRequest(reader)
		if err == nil {
			parsedHeader, body = parsed.Header, parsed.Body
			if parsed.Host != "" {
				parsedHeader.Set("Host", parsed.Host)
			}
		}
	}
	if needs.fields {
		message.fields = parsedHeader
	}
	sameParser := response == bytes.HasPrefix(raw, []byte("HTTP/"))
	isGzip := body != nil && strings.EqualFold(parsedHeader.Get("Content-Encoding"), "gzip")
	if body != nil {
		if needs.body {
			data, _ := io.ReadAll(io.LimitReader(body, int64(limit)))
			message.body = string(data)
			if needs.decoded && sameParser && isGzip {
				var src io.Reader = bytes.NewReader(data)
				if len(data) == limit {
					src = io.MultiReader(src, body)
				}
				message.decoded, message.decodedView = gunzipBody(src, limit)
			}
		} else if needs.decoded && sameParser && isGzip {
			message.decoded, message.decodedView = gunzipBody(body, limit)
		}
		body.Close()
	} else if needs.body && found {
		message.body = string(payload)
	}
	if needs.decoded && !sameParser {
		message.decoded, message.decodedView = session.DecodedBody(raw, limit)
	}
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
	text  string
	round int
	// folded is text as rule prefilters search it (foldForPrefilter).
	folded string
}

func decodeViews(text string) []decodedView {
	variants := []decodedView{{text: text, round: 0, folded: foldForPrefilter(text)}}
	for round := 1; round <= 2; round++ {
		decoded := decodePercent(text)
		if decoded == text {
			break
		}
		variants = append(variants, decodedView{text: decoded, round: round, folded: foldForPrefilter(decoded)})
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

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func decodePercent(text string) string {
	if strings.IndexAny(text, "%+") < 0 {
		return text
	}
	if decoded, err := url.QueryUnescape(text); err == nil {
		return decoded
	}
	var out strings.Builder
	out.Grow(len(text))
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '+':
			out.WriteByte(' ')
		case '%':
			if i+2 < len(text) {
				hi, ok1 := fromHex(text[i+1])
				lo, ok2 := fromHex(text[i+2])
				if ok1 && ok2 {
					out.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
			out.WriteByte('%')
		default:
			out.WriteByte(text[i])
		}
	}
	return out.String()
}

type scanPath struct {
	when   time.Time
	status int
}
type scanState struct {
	paths map[string]scanPath
	// missing counts paths whose latest status is HTTP 404.
	missing   int
	lastAlert time.Time
}

// scanSeen records one sighting of a path. A path seen again leaves its older
// sighting in the heap; expiry skips sightings that no longer match the path.
type scanSeen struct {
	when         time.Time
	client, path string
}

// scanHeap orders sightings oldest first, so expiry only touches the paths
// that leave the window instead of every tracked path on every transaction.
type scanHeap []scanSeen

func (h scanHeap) Len() int           { return len(h) }
func (h scanHeap) Less(i, j int) bool { return h[i].when.Before(h[j].when) }
func (h scanHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *scanHeap) Push(x any)        { *h = append(*h, x.(scanSeen)) }
func (h *scanHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	old[len(old)-1] = scanSeen{}
	*h = old[:len(old)-1]
	return x
}

type scanTracker struct {
	sync.Mutex
	clients map[string]*scanState
	seen    scanHeap
	// tracked is the number of paths across all clients.
	tracked int
	skipped scanSkipped
}

// scanSkipped counts transactions left out of scan correlation by its limits.
type scanSkipped struct {
	// Clients counts transactions from a new client while maxScanClients
	// other clients were tracked.
	Clients uint64 `json:"clients,omitempty"`
	// Paths counts transactions from a client already tracking maxScanPaths paths.
	Paths uint64 `json:"paths,omitempty"`
}

// Scan correlation tracks at most this many clients and paths per client.
const (
	maxScanClients = 2000
	maxScanPaths   = 1000
)

var scans = scanTracker{clients: map[string]*scanState{}}

func scan(t Transaction) *Alert { return scanWithState(t, &scans, scanWindow, scanThreshold) }

// expire drops every path last seen more than scanWindow before now, and
// clients left without paths, exactly as a full sweep would.
func (scans *scanTracker) expire(now time.Time, scanWindow time.Duration) {
	for len(scans.seen) > 0 && now.Sub(scans.seen[0].when) > scanWindow {
		seen := heap.Pop(&scans.seen).(scanSeen)
		s := scans.clients[seen.client]
		if s == nil {
			continue
		}
		x, ok := s.paths[seen.path]
		if !ok || !x.when.Equal(seen.when) {
			continue
		}
		delete(s.paths, seen.path)
		scans.tracked--
		if x.status == 404 {
			s.missing--
		}
		if len(s.paths) == 0 {
			delete(scans.clients, seen.client)
		}
	}
}

// compact rebuilds the heap from the live paths once superseded sightings
// dominate it, so a client hitting one path at a high rate stays bounded.
func (scans *scanTracker) compact() {
	if len(scans.seen) <= 2*scans.tracked+4096 {
		return
	}
	seen := make(scanHeap, 0, scans.tracked)
	for client, s := range scans.clients {
		for path, x := range s.paths {
			seen = append(seen, scanSeen{x.when, client, path})
		}
	}
	heap.Init(&seen)
	scans.seen = seen
}

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
	scans.expire(now, scanWindow)
	s := scans.clients[host]
	if s == nil {
		if len(scans.clients) >= maxScanClients {
			scans.skipped.Clients++
			return nil
		}
		s = &scanState{paths: map[string]scanPath{}}
		scans.clients[host] = s
	}
	path, _, _ := strings.Cut(t.URL, "?")
	if old, ok := s.paths[path]; ok {
		if old.status == 404 {
			s.missing--
		}
	} else {
		if len(s.paths) >= maxScanPaths {
			scans.skipped.Paths++
			return nil
		}
		scans.tracked++
	}
	s.paths[path] = scanPath{now, t.Status}
	if t.Status == 404 {
		s.missing++
	}
	heap.Push(&scans.seen, scanSeen{now, host, path})
	scans.compact()
	missing := s.missing
	if len(s.paths) >= scanThreshold && missing*2 >= len(s.paths) && now.Sub(s.lastAlert) >= scanWindow {
		s.lastAlert = now
		return &Alert{Rule: "SCAN-001", Version: 1, Severity: "medium", Field: "path-window", Match: fmt.Sprintf("%d distinct paths, %d HTTP 404 within %s", len(s.paths), missing, scanWindow)}
	}
	return nil
}
