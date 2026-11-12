package main

import (
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

// webServer exposes the same read-only queries as the TUI over a token-protected HTTP API.
type webServer struct {
	token   string
	roots   []string
	refresh time.Duration

	mu       sync.Mutex
	sessions map[string]sessionEntry
	stores   map[string]*Store
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
	return &webServer{token: token, roots: roots, refresh: refresh, sessions: map[string]sessionEntry{}, stores: map[string]*Store{}}
}

func webSessionID(dir string) string {
	sum := sha256.Sum256([]byte(dir))
	return hex.EncodeToString(sum[:8])
}

func (w *webServer) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for dir, s := range w.stores {
		s.db.Close()
		delete(w.stores, dir)
	}
}

func (w *webServer) discover(ctx context.Context) sessionsFound {
	found := discoverSessions(ctx, w.roots)
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
		w.discover(ctx)
		w.mu.Lock()
		entry, ok = w.sessions[id]
		w.mu.Unlock()
		if !ok {
			return nil, errWebSessionNotFound
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if s := w.stores[entry.Dir]; s != nil {
		return s, nil
	}
	s, err := openStore(entry.Dir)
	if err != nil {
		return nil, fmt.Errorf("无法打开会话: %w", err)
	}
	w.stores[entry.Dir] = s
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
	mux.HandleFunc("GET /api/sessions/{sid}/requests/{rid}", w.handleDetail)
	mux.HandleFunc("GET /api/sessions/{sid}/requests/{rid}/export", w.handleExport)
	static, _ := fs.Sub(webAssets, "web")
	files := http.FileServerFS(static)
	mux.HandleFunc("GET /{file}", func(rw http.ResponseWriter, r *http.Request) {
		switch r.PathValue("file") {
		case "app.css", "app.js":
			files.ServeHTTP(rw, r)
		default:
			http.NotFound(rw, r)
		}
	})
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, r *http.Request) { files.ServeHTTP(rw, r) })
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		header := rw.Header()
		// Captured traffic is attacker-controlled, so the page may only load its own embedded assets.
		header.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
			want := sha256.Sum256([]byte(w.token))
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				webError(rw, http.StatusUnauthorized, errors.New("访问令牌无效"))
				return
			}
		}
		mux.ServeHTTP(rw, r)
	})
}

func (w *webServer) handleSessions(rw http.ResponseWriter, r *http.Request) {
	found := w.discover(r.Context())
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

func (w *webServer) handleRequests(rw http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	get := func(name string) string { return strings.TrimSpace(q.Get(name)) }
	filter := tuiFilter{Client: get("client"), Rule: get("rule"), Severity: get("severity"), Keyword: get("keyword"), Service: get("service")}
	if filter.Severity != "" && filter.Severity != "low" && filter.Severity != "medium" && filter.Severity != "high" {
		webError(rw, http.StatusBadRequest, errors.New("级别必须是 low、medium 或 high"))
		return
	}
	if since := get("since"); since != "" {
		stamp, err := time.Parse(time.RFC3339, since)
		if err != nil {
			webError(rw, http.StatusBadRequest, errors.New("起始时间需要 RFC3339 格式"))
			return
		}
		filter.Since = stamp.UTC().Format(indexTimeFormat)
	}
	page, _ := strconv.Atoi(get("page"))
	page = max(0, page)
	var anchor *tuiRow
	if page > 0 && get("anchor_id") != "" {
		anchor = &tuiRow{ID: get("anchor_id"), Time: get("anchor_time")}
	}
	s := w.sessionStore(rw, r)
	if s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	snapshot, err := loadTUISnapshot(ctx, s, filter, get("alerts") == "1", page, "", anchor)
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	rows := make([]webRow, 0, len(snapshot.Rows))
	for _, row := range snapshot.Rows {
		rows = append(rows, webRow{ID: row.ID, Time: row.Time, Client: row.Client, Method: row.Method, Host: row.Host, URL: row.URL, Status: row.Status, Severity: row.Severity, Incomplete: row.Incomplete, Truncated: row.Truncated})
	}
	webJSON(rw, http.StatusOK, map[string]any{
		"rows": rows, "count": snapshot.Count, "page": snapshot.Page, "page_size": 100,
		"stats": snapshot.Stats, "status_warning": snapshot.StatusWarning, "dir": s.dir,
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
		webError(rw, http.StatusNotFound, errors.New("该记录不存在或已被保留期清理"))
		return nil, t, nil, false
	}
	if err == nil {
		err = json.Unmarshal(b, &t)
	}
	if err != nil {
		webError(rw, http.StatusInternalServerError, fmt.Errorf("读取请求详情: %w", err))
		return nil, t, nil, false
	}
	return s, t, b, true
}

func (w *webServer) handleDetail(rw http.ResponseWriter, r *http.Request) {
	_, t, _, ok := w.transaction(rw, r)
	if !ok {
		return
	}
	decoded, view := session.DecodedBody(t.Request, 1<<20)
	result := map[string]any{"request_text": session.SafeText(t.Request), "response_text": session.SafeText(t.Response), "decoded_body": strings.ToValidUTF8(decoded, "�"), "decoded_view": view}
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

func runWeb(dir, root, listen string, allowRemote bool, refresh time.Duration) error {
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
	server := &http.Server{Handler: w.handler(), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	address := listener.Addr().String()
	// The token travels in the URL fragment, which browsers never send to the server.
	fmt.Fprintf(os.Stderr, "Web 界面  http://%s/#token=%s\n会话目录  %s\n按 Ctrl+C 停止\n", address, token, strings.Join(roots, " · "))
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
