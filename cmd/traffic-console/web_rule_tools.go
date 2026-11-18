package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Sunmedalia/traffic/internal/session"
)

// webRuleHit is one rule's footprint in a session's current analysis result.
type webRuleHit struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Requests int    `json:"requests"`
	First    string `json:"first"`
	Last     string `json:"last"`
}

// handleRuleHits counts, for every rule, the requests it flagged in a session.
// It also returns the rule set that produced those results, so the editor can
// tell a rule that never matched from one the session was never analyzed with.
func (w *webServer) handleRuleHits(rw http.ResponseWriter, r *http.Request) {
	s := w.sessionStore(rw, r)
	if s == nil {
		return
	}
	defer s.db.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(json_extract(hit.value,'$.rule'),''),COALESCE(max(json_extract(hit.value,'$.severity')),''),count(DISTINCT requests.id),min(requests.time),max(requests.time) FROM requests, json_each(CAST(requests.data AS TEXT),'$.alerts') hit WHERE alert>0 GROUP BY 1 ORDER BY 3 DESC,1`)
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()
	hits := []webRuleHit{}
	for rows.Next() {
		var hit webRuleHit
		if err = rows.Scan(&hit.Rule, &hit.Severity, &hit.Requests, &hit.First, &hit.Last); err != nil {
			webError(rw, http.StatusInternalServerError, err)
			return
		}
		hits = append(hits, hit)
	}
	if err = rows.Err(); err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	var total, alerted int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(alert>0),0) FROM requests").Scan(&total, &alerted); err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	result := map[string]any{"hits": hits, "total": total, "alerted": alerted, "analyzed": s.analysis != nil}
	if s.analysis != nil {
		result["rules"] = s.analysis.Rules
		result["completed"] = s.analysis.Completed
	}
	if s.analysisNote != "" {
		result["note"] = s.analysisNote
	}
	webJSON(rw, http.StatusOK, result)
}

const maxRuleTestBytes = 1 << 20

// handleRuleTest runs unsaved rule content against one captured request or a
// pasted HTTP message. It only reads: nothing is written to the session.
func (w *webServer) handleRuleTest(rw http.ResponseWriter, r *http.Request) {
	var input struct {
		Content   string `json:"content"`
		SessionID string `json:"session_id"`
		RequestID string `json:"request_id"`
		Request   string `json:"request"`
		Response  string `json:"response"`
	}
	if err := decodeWebJSON(rw, r, &input); err != nil {
		webError(rw, http.StatusBadRequest, err)
		return
	}
	var rs []Rule
	var err error
	if strings.TrimSpace(input.Content) == "" {
		rs, err = rulesFromYAML(nil)
	} else {
		rs, err = validateRuleContent(input.Content)
	}
	if err != nil {
		webError(rw, http.StatusUnprocessableEntity, err)
		return
	}
	var t Transaction
	source := "manual"
	if input.SessionID != "" || input.RequestID != "" {
		source = "session"
		var ok bool
		if t, ok = w.ruleTestTransaction(rw, r.Context(), input.SessionID, input.RequestID); !ok {
			return
		}
	} else {
		if t, err = manualRuleTestTransaction(input.Request, input.Response); err != nil {
			webError(rw, http.StatusBadRequest, err)
			return
		}
	}
	warnings := []string{}
	if source == "manual" {
		if _, reasons, parseErr := session.ParseRequest(t.Request); parseErr != nil {
			warnings = append(warnings, "请求无法按 HTTP 报文解析（头部需以空行结束），request.header.* 与 request.body 字段可能无法命中")
		} else if len(reasons) > 0 {
			warnings = append(warnings, "请求不符合严格 HTTP 语法，已按宽松方式解析（"+strings.Join(reasons, ", ")+"），与采集还原的处理一致")
		}
		if len(t.Response) > 0 {
			if _, parseErr := http.ReadResponse(bufio.NewReader(bytes.NewReader(t.Response)), nil); parseErr != nil {
				warnings = append(warnings, "响应无法按 HTTP 报文解析，response.header.* 与 response.body 字段可能无法命中")
			}
		}
	}
	recorded := t.Alerts
	if recorded == nil {
		recorded = []Alert{}
	}
	matched := detectWithRules(t, rs)
	if matched == nil {
		matched = []Alert{}
	}
	custom := []string{}
	for _, rule := range rs[len(builtinRules):] {
		custom = append(custom, rule.ID)
	}
	webJSON(rw, http.StatusOK, map[string]any{
		"source": source, "alerts": matched, "recorded": recorded, "total_rules": len(rs), "custom_rules": custom, "warnings": warnings,
		"transaction": map[string]any{"id": t.ID, "time": t.Time, "method": t.Method, "host": t.Host, "url": t.URL, "status": t.Status, "client": t.Client,
			"request_bytes": len(t.Request), "response_bytes": len(t.Response)},
	})
}

func (w *webServer) ruleTestTransaction(rw http.ResponseWriter, ctx context.Context, sid, rid string) (Transaction, bool) {
	var t Transaction
	if sid == "" || rid == "" {
		webError(rw, http.StatusBadRequest, errors.New("请同时选择会话和请求"))
		return t, false
	}
	s, err := w.store(ctx, sid)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errWebSessionNotFound) {
			status = http.StatusNotFound
		}
		webError(rw, status, err)
		return t, false
	}
	defer s.db.Close()
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var b []byte
	err = s.db.QueryRowContext(queryCtx, "SELECT data FROM requests WHERE id=?", rid).Scan(&b)
	if err == sql.ErrNoRows {
		webError(rw, http.StatusNotFound, errors.New("该记录不存在或已被保留期清理"))
		return t, false
	}
	if err == nil {
		err = json.Unmarshal(b, &t)
	}
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return t, false
	}
	return t, true
}

// Pasted messages usually arrive with bare newlines; detection expects wire format.
func wireMessage(text string) []byte {
	if !strings.Contains(text, "\r\n") {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	return []byte(text)
}

func manualRuleTestTransaction(request, response string) (Transaction, error) {
	var t Transaction
	if len(request) > maxRuleTestBytes || len(response) > maxRuleTestBytes {
		return t, errors.New("测试请求和响应各不能超过 1 MiB")
	}
	if !utf8.ValidString(request) || !utf8.ValidString(response) {
		return t, errors.New("测试内容必须是 UTF-8 文本")
	}
	request = strings.TrimLeft(request, "\r\n")
	line, _, _ := strings.Cut(request, "\n")
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.HasPrefix(fields[2], "HTTP/") {
		return t, errors.New("请求第一行应为“方法 URL 协议”，例如 GET /index.php?id=1 HTTP/1.1")
	}
	t.ID, t.Time, t.Method, t.URL = "manual", time.Now().UTC(), fields[0], fields[1]
	t.Request = wireMessage(request)
	if strings.TrimSpace(response) != "" {
		response = strings.TrimLeft(response, "\r\n")
		t.Response = wireMessage(response)
		if status := strings.Fields(strings.SplitN(response, "\n", 2)[0]); len(status) >= 2 {
			t.Status, _ = strconv.Atoi(status[1])
		}
	}
	for _, header := range strings.Split(request, "\n")[1:] {
		header = strings.TrimSpace(header)
		if header == "" {
			break
		}
		if name, value, ok := strings.Cut(header, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			t.Host = strings.TrimSpace(value)
		}
	}
	return t, nil
}
