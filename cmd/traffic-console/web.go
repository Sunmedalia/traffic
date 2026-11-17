package main

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

//go:embed web/index.html web/app.css web/app.js
var webAssets embed.FS

// webAssetTags lets browsers revalidate the embedded assets instead of
// downloading them on every page load.
var webAssetTags = func() map[string]string {
	tags := map[string]string{}
	for _, name := range []string{"index.html", "app.css", "app.js"} {
		data, err := webAssets.ReadFile("web/" + name)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		tags[name] = `"` + hex.EncodeToString(sum[:8]) + `"`
	}
	return tags
}()

type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
}

func (w *gzipResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *gzipResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if status == http.StatusNoContent || status == http.StatusNotModified || status == http.StatusResetContent {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
	w.gz = gzip.NewWriter(w.ResponseWriter)
}

func (w *gzipResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.gz == nil {
		return w.ResponseWriter.Write(p)
	}
	return w.gz.Write(p)
}

func (w *gzipResponseWriter) Close() error {
	if w.gz != nil {
		return w.gz.Close()
	}
	return nil
}

func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(fields[0]), "gzip") {
			continue
		}
		allowed := true
		for _, param := range fields[1:] {
			value := strings.TrimSpace(param)
			if strings.HasPrefix(value, "q=") {
				quality, err := strconv.ParseFloat(strings.TrimPrefix(value, "q="), 64)
				if err == nil && quality <= 0 {
					allowed = false
				}
			}
		}
		return allowed
	}
	return false
}

// webServer keeps capture evidence read-only; managed rules and local analysis
// are explicit token-protected writes.
type webServer struct {
	token   string
	roots   []string
	refresh time.Duration

	mu          sync.Mutex
	sessions    map[string]sessionEntry
	discovery   *discoveryCache
	ruleLibrary *ruleLibrary
	ctx         context.Context
	cancel      context.CancelFunc
	jobMu       sync.Mutex
	job         *webAnalysisJob
	jobCancel   context.CancelFunc
	jobs        sync.WaitGroup

	summaryMu sync.Mutex
	summaries map[string]summaryCacheEntry
}

type summaryCacheEntry struct {
	revision string
	data     map[string]any
}

type webSession struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Host         string    `json:"host"`
	Dir          string    `json:"dir"`
	Started      time.Time `json:"started"`
	State        string    `json:"state"`
	Transactions uint64    `json:"transactions"`
	Alerts       uint64    `json:"alerts"`
	CountsKnown  bool      `json:"counts_known"`
	Problem      string    `json:"problem,omitempty"`
}

type webRow struct {
	ID         string `json:"id"`
	Time       string `json:"time"`
	Client     string `json:"client"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Severity   string `json:"severity"`
	Incomplete bool   `json:"incomplete"`
	Truncated  bool   `json:"truncated"`
}

var errWebSessionNotFound = errors.New("会话不存在，请重新扫描")

func newWebServer(roots []string, token string, refresh time.Duration) *webServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &webServer{token: token, roots: roots, refresh: refresh, sessions: map[string]sessionEntry{}, discovery: newDiscoveryCache(), summaries: map[string]summaryCacheEntry{}, ctx: ctx, cancel: cancel}
}

func webSessionID(dir string) string {
	sum := sha256.Sum256([]byte(dir))
	return hex.EncodeToString(sum[:8])
}

func (w *webServer) close() {
	w.cancel()
	w.jobs.Wait()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ruleLibrary != nil {
		w.ruleLibrary.root.Close()
	}
}

func (w *webServer) discover(ctx context.Context, force bool) sessionsFound {
	if force {
		w.discovery.clear()
	}
	found := discoverSessions(ctx, w.roots, w.discovery)
	if ctx.Err() != nil {
		return found
	}
	sessions := make(map[string]sessionEntry, len(found.Entries))
	for _, entry := range found.Entries {
		sessions[webSessionID(entry.Dir)] = entry
	}
	w.mu.Lock()
	w.sessions = sessions
	w.mu.Unlock()
	return found
}

// Session IDs only resolve to directories found under the configured roots.
func (w *webServer) store(ctx context.Context, id string) (*Store, error) {
	w.mu.Lock()
	entry, ok := w.sessions[id]
	w.mu.Unlock()
	if !ok {
		w.discover(ctx, true)
		w.mu.Lock()
		entry, ok = w.sessions[id]
		w.mu.Unlock()
		if !ok {
			return nil, errWebSessionNotFound
		}
	}
	s, err := openStore(entry.Dir)
	if err != nil {
		return nil, fmt.Errorf("无法打开会话: %w", err)
	}
	return s, nil
}

func webJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	json.NewEncoder(rw).Encode(v)
}

func webError(rw http.ResponseWriter, status int, err error) {
	webJSON(rw, status, map[string]string{"error": err.Error()})
}

func (w *webServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/sessions", w.handleSessions)
	mux.HandleFunc("GET /api/sessions/{sid}/requests", w.handleRequests)
	mux.HandleFunc("GET /api/sessions/{sid}/requests/{rid}/meta", w.handleRequestMeta)
	mux.HandleFunc("GET /api/sessions/{sid}/timeline", w.handleTimeline)
	mux.HandleFunc("GET /api/sessions/{sid}/summary", w.handleSummary)
	mux.HandleFunc("GET /api/sessions/{sid}/requests/{rid}", w.handleDetail)
	mux.HandleFunc("GET /api/sessions/{sid}/requests/{rid}/export", w.handleExport)
	mux.HandleFunc("GET /api/rules", w.handleRuleList)
	mux.HandleFunc("POST /api/rules/validate", w.handleRuleValidate)
	mux.HandleFunc("GET /api/rules/{name}", w.handleRuleFile)
	mux.HandleFunc("PUT /api/rules/{name}", w.handleRuleFile)
	mux.HandleFunc("DELETE /api/rules/{name}", w.handleRuleFile)
	mux.HandleFunc("POST /api/sessions/{sid}/analyze", w.handleAnalyze)
	mux.HandleFunc("GET /api/analysis", w.handleAnalysisStatus)
	mux.HandleFunc("DELETE /api/analysis", w.handleAnalysisCancel)
	static, _ := fs.Sub(webAssets, "web")
	files := http.FileServerFS(static)
	serveAsset := func(name string) http.HandlerFunc {
		return func(rw http.ResponseWriter, r *http.Request) {
			if tag := webAssetTags[name]; tag != "" {
				rw.Header().Set("ETag", tag)
				rw.Header().Set("Cache-Control", "no-cache")
				if r.Header.Get("If-None-Match") == tag {
					rw.WriteHeader(http.StatusNotModified)
					return
				}
			}
			files.ServeHTTP(rw, r)
		}
	}
	appCSS, appJS, index := serveAsset("app.css"), serveAsset("app.js"), serveAsset("index.html")
	mux.HandleFunc("GET /{file}", func(rw http.ResponseWriter, r *http.Request) {
		switch r.PathValue("file") {
		case "app.css":
			appCSS.ServeHTTP(rw, r)
		case "app.js":
			appJS.ServeHTTP(rw, r)
		default:
			http.NotFound(rw, r)
		}
	})
	mux.HandleFunc("GET /{$}", index.ServeHTTP)
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		header := rw.Header()
		// Captured traffic is attacker-controlled, so the page may only load its own embedded assets.
		header.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			header.Set("Cache-Control", "no-store")
			got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
			want := sha256.Sum256([]byte(w.token))
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				webError(rw, http.StatusUnauthorized, errors.New("访问令牌无效"))
				return
			}
		} else {
			header.Set("Cache-Control", "no-cache")
		}
		header.Add("Vary", "Accept-Encoding")
		if acceptsGzip(r.Header.Get("Accept-Encoding")) && r.Header.Get("Range") == "" && !strings.HasSuffix(r.URL.Path, "/export") {
			writer := &gzipResponseWriter{ResponseWriter: rw}
			defer writer.Close()
			mux.ServeHTTP(writer, r)
			return
		}
		mux.ServeHTTP(rw, r)
	})
}

func (w *webServer) handleSessions(rw http.ResponseWriter, r *http.Request) {
	found := w.discover(r.Context(), r.URL.Query().Get("rescan") == "1")
	list := make([]webSession, 0, len(found.Entries))
	for _, entry := range found.Entries {
		list = append(list, webSession{
			ID: webSessionID(entry.Dir), Name: entry.Name, Host: entry.Host, Dir: entry.Dir, Started: entry.Started,
			State: entry.Stats.State, Transactions: entry.Stats.Transactions, Alerts: entry.Stats.Alerts,
			CountsKnown: entry.CountsKnown, Problem: entry.Problem,
		})
	}
	webJSON(rw, http.StatusOK, map[string]any{"sessions": list, "roots": w.roots, "warning": found.Warning, "refresh_ms": w.refresh.Milliseconds()})
}

func (w *webServer) sessionStore(rw http.ResponseWriter, r *http.Request) *Store {
	s, err := w.store(r.Context(), r.PathValue("sid"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errWebSessionNotFound) {
			status = http.StatusNotFound
		}
		webError(rw, status, err)
		return nil
	}
	return s
}

// webFilter validates the query parameters shared by the list, timeline and summary endpoints.
func webFilter(r *http.Request) (tuiFilter, func(string) string, error) {
	q := r.URL.Query()
	get := func(name string) string { return strings.TrimSpace(q.Get(name)) }
	filter := tuiFilter{UntilExclusive: true, Client: get("client"), Rule: get("rule"), Severity: get("severity"), Keyword: get("keyword"), Service: get("service"), Method: get("method"), Status: get("status")}
	if filter.Severity != "" && filter.Severity != "low" && filter.Severity != "medium" && filter.Severity != "high" {
		return filter, get, errors.New("级别必须是 low、medium 或 high")
	}
	if filter.Status != "" && filter.Status != "pending" {
		class := len(filter.Status) == 3 && filter.Status[0] >= '1' && filter.Status[0] <= '5' && filter.Status[1:] == "xx"
		if code, err := strconv.Atoi(filter.Status); !class && (err != nil || code < 100 || code > 999) {
			return filter, get, errors.New("状态必须是 pending、2xx 这样的类别或具体状态码")
		}
	}
	for name, target := range map[string]*string{"since": &filter.Since, "until": &filter.Until} {
		value := get(name)
		if value == "" {
			continue
		}
		stamp, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return filter, get, errors.New("时间范围需要 RFC3339 格式")
		}
		*target = stamp.UTC().Format(indexTimeFormat)
	}
	return filter, get, nil
}

func (w *webServer) handleRequests(rw http.ResponseWriter, r *http.Request) {
	filter, get, err := webFilter(r)
	if err != nil {
		webError(rw, http.StatusBadRequest, err)
		return
	}
	page, _ := strconv.Atoi(get("page"))
	page = max(0, page)
	limit := 100
	if raw := get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 500 {
			webError(rw, http.StatusBadRequest, errors.New("limit 必须是 1 到 500 之间的整数"))
			return
		}
	}
	var anchor *tuiRow
	if page > 0 && get("anchor_id") != "" {
		anchor = &tuiRow{ID: get("anchor_id"), Time: get("anchor_time")}
	}
	s := w.sessionStore(rw, r)
	if s == nil {
		return
	}
	defer s.db.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	snapshot, err := loadTUISnapshot(ctx, s, filter, get("alerts") == "1", page, "", anchor, limit)
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	rows := make([]webRow, 0, len(snapshot.Rows))
	for _, row := range snapshot.Rows {
		rows = append(rows, webRow{ID: row.ID, Time: row.Time, Client: row.Client, Method: row.Method, Host: row.Host, URL: row.URL, Status: row.Status, Severity: row.Severity, Incomplete: row.Incomplete, Truncated: row.Truncated})
	}
	webJSON(rw, http.StatusOK, map[string]any{
		"rows": rows, "count": snapshot.Count, "page": snapshot.Page, "page_size": limit,
		"stats": snapshot.Stats, "status_warning": snapshot.StatusWarning, "dir": s.dir, "coverage_warning": session.CoverageWarning,
	})
}

func (w *webServer) transaction(rw http.ResponseWriter, r *http.Request) (*Store, Transaction, []byte, bool) {
	var t Transaction
	s := w.sessionStore(rw, r)
	if s == nil {
		return nil, t, nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var b []byte
	err := s.db.QueryRowContext(ctx, "SELECT data FROM requests WHERE id=?", r.PathValue("rid")).Scan(&b)
	if err == sql.ErrNoRows {
		s.db.Close()
		webError(rw, http.StatusNotFound, errors.New("该记录不存在或已被保留期清理"))
		return nil, t, nil, false
	}
	if err == nil {
		err = json.Unmarshal(b, &t)
	}
	if err != nil {
		s.db.Close()
		webError(rw, http.StatusInternalServerError, fmt.Errorf("读取请求详情: %w", err))
		return nil, t, nil, false
	}
	return s, t, b, true
}

// handleRequestMeta returns only the fields that change when a response arrives.
// Pending detail views poll this instead of downloading request and response bodies.
func (w *webServer) handleRequestMeta(rw http.ResponseWriter, r *http.Request) {
	s := w.sessionStore(rw, r)
	if s == nil {
		return
	}
	defer s.db.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var status, alertCount int
	var incomplete, truncated bool
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(json_extract(CAST(data AS TEXT),'$.status'),0),
 COALESCE(json_extract(CAST(data AS TEXT),'$.incomplete'),0),
 COALESCE(json_extract(CAST(data AS TEXT),'$.truncated'),0),
 COALESCE(json_array_length(json_extract(CAST(data AS TEXT),'$.alerts')),0)
 FROM requests WHERE id=?`, r.PathValue("rid")).Scan(&status, &incomplete, &truncated, &alertCount)
	if err == sql.ErrNoRows {
		webError(rw, http.StatusNotFound, errors.New("该记录不存在或已被保留期清理"))
		return
	}
	if err != nil {
		webError(rw, http.StatusInternalServerError, fmt.Errorf("读取请求状态: %w", err))
		return
	}
	webJSON(rw, http.StatusOK, map[string]any{"status": status, "incomplete": incomplete, "truncated": truncated, "alert_count": alertCount})
}

func (w *webServer) handleDetail(rw http.ResponseWriter, r *http.Request) {
	s, t, _, ok := w.transaction(rw, r)
	if !ok {
		return
	}
	defer s.db.Close()
	decoded, view := session.DecodedBody(t.Request, 1<<20)
	responseDecoded, responseView := session.DecodedBody(t.Response, 1<<20)
	result := map[string]any{
		"request_text": session.SafeText(t.Request), "response_text": session.SafeText(t.Response),
		"decoded_body": strings.ToValidUTF8(decoded, "�"), "decoded_view": view,
		"response_decoded_body": strings.ToValidUTF8(responseDecoded, "�"), "response_decoded_view": responseView,
	}
	// The texts above replace the base64 byte fields.
	t.Request, t.Response = nil, nil
	result["transaction"] = t
	webJSON(rw, http.StatusOK, result)
}

func (w *webServer) handleExport(rw http.ResponseWriter, r *http.Request) {
	s, t, b, ok := w.transaction(rw, r)
	if !ok {
		return
	}
	defer s.db.Close()
	dir, err := os.MkdirTemp("", "traffic-export-*")
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "evidence.zip")
	if err = exportEvidence(s, t, b, path); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "stop capture before exporting evidence") {
			status, err = http.StatusConflict, errors.New("采集仍在进行，请停止采集后再导出证据")
		}
		webError(rw, status, err)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	defer file.Close()
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return -1
	}, t.ID)
	if info, err := file.Stat(); err == nil {
		rw.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	}
	rw.Header().Set("Content-Type", "application/zip")
	rw.Header().Set("Content-Disposition", `attachment; filename="evidence-`+name+`.zip"`)
	io.Copy(rw, file)
}

func webLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func runWeb(dir, root, rulesDir, listen string, allowRemote bool, refresh time.Duration) error {
	if refresh < 500*time.Millisecond {
		return errors.New("--refresh 在 Web 模式下不能小于 500ms")
	}
	if !webLoopback(listen) && !allowRemote {
		return fmt.Errorf("--listen %s 不是回环地址；连接未加密，建议保持 127.0.0.1 并使用 SSH 端口转发，确需直接暴露时添加 --allow-remote", listen)
	}
	roots := sessionRoots(root)
	if dir != "" {
		roots = []string{sessionPath(dir)}
		s, err := openStore(roots[0])
		if err != nil {
			return fmt.Errorf("无法打开会话: %w", err)
		}
		s.db.Close()
	}
	token := os.Getenv("TRAFFIC_WEB_TOKEN")
	if token == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		token = hex.EncodeToString(raw)
	} else if len(token) < 16 {
		return errors.New("TRAFFIC_WEB_TOKEN 至少需要 16 个字符")
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	w := newWebServer(roots, token, refresh)
	defer w.close()
	w.ruleLibrary, err = openRuleLibrary(rulesDir)
	if err != nil {
		listener.Close()
		return fmt.Errorf("规则目录: %w", err)
	}
	server := &http.Server{Handler: w.handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	address := listener.Addr().String()
	// The token travels in the URL fragment, which browsers never send to the server.
	fmt.Fprintf(os.Stderr, "Web 界面  http://%s/#token=%s\n会话目录  %s\n按 Ctrl+C 停止\n", address, token, strings.Join(roots, " · "))
	fmt.Fprintln(os.Stderr, "规则目录 ", w.ruleLibrary.dir)
	if !webLoopback(listen) {
		fmt.Fprintln(os.Stderr, "警告  正在非回环地址上以明文 HTTP 提供证据，令牌和流量内容可被链路上的第三方读取")
	}
	failed := make(chan error, 1)
	go func() { failed <- server.Serve(listener) }()
	select {
	case err = <-failed:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = server.Shutdown(shutdown); err != nil {
		return server.Close()
	}
	return nil
}
