package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/Sunmedalia/traffic/internal/session"
)

// tuiFilter applies to persisted transactions, including records written by v1.
type tuiFilter struct {
	Client, Rule, Severity, Since, Keyword, Service string
	// Until is inclusive in the TUI and exclusive in the web interface.
	// Method and Status are only set by the web interface.
	Until, Method, Status string
	UntilExclusive        bool
	// Web-only refinements. Decode is how many URL-decoding rounds the keyword
	// and exclusions see (0 matches the stored text); Exclude holds terms that
	// must not appear in Host or URL; Param is a query parameter name.
	Decode     int
	Exclude    string
	Param      string
	HideStatic bool
}

// maxFilterDecodeRounds mirrors the bound enforced inside traffic_url_decode.
const maxFilterDecodeRounds = index.MaxURLDecodeRounds

// staticExtensions are the asset types hidden by the web "隐藏静态资源" toggle.
var staticExtensions = []string{"js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "avif", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "webm"}

type tuiRow struct {
	ID, Time, Client, Method, Host, URL, Severity, Rule string
	Status                                              int
	Incomplete, Truncated                               bool
}

// tuiDetailMeta is a lightweight fingerprint of an open detail row queried from
// entries before fetching and decoding the full transaction body from records.
type tuiDetailMeta struct {
	ID         string
	Status     int
	Incomplete bool
	Truncated  bool
	AlertCount int
	Alerts     string
}

type tuiSnapshot struct {
	Rows            []tuiRow
	Count           int
	Page            int
	Stats           Stats
	StatusWarning   string
	Detail          *Transaction
	DetailMeta      *tuiDetailMeta
	DetailUnchanged bool
	DetailMissing   bool
	// Newer counts matching records above an anchored first row.
	Newer int
}

// severityRank orders levels so a severity filter means "at least".
func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

const sqlSeverityRank = `CASE json_extract(a.value,'$.severity') WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`

func (f tuiFilter) where(alertsOnly bool) (string, []any) {
	clauses := []string{"time>=?"}
	args := []any{f.Since}
	if f.Until != "" {
		operator := "time<=?"
		if f.UntilExclusive {
			operator = "time<?"
		}
		clauses = append(clauses, operator)
		args = append(args, f.Until)
	}
	if alertsOnly || f.Rule != "" || f.Severity != "" {
		clauses = append(clauses, "alert>0")
	}
	if f.Client != "" {
		prefix := f.Client + ":%"
		if net.ParseIP(f.Client) != nil && strings.Contains(f.Client, ":") {
			prefix = "[" + f.Client + "]:%"
		}
		clauses = append(clauses, "(client=? OR client LIKE ? ESCAPE '\\')")
		prefix = escapeLike(strings.TrimSuffix(prefix, "%")) + "%"
		args = append(args, f.Client, prefix)
	}
	if f.Rule != "" {
		clauses = append(clauses, `EXISTS (SELECT 1 FROM json_each(entries.alerts) a WHERE json_extract(a.value,'$.rule')=? AND `+sqlSeverityRank+`>=?)`)
		args = append(args, f.Rule, severityRank(f.Severity))
	} else if f.Severity != "" {
		// The stored maximum rank answers "any alert at least this severe".
		clauses = append(clauses, "severity>=?")
		args = append(args, severityRank(f.Severity))
	}
	if f.Service != "" {
		clauses = append(clauses, "service=?")
		args = append(args, f.Service)
	}
	if f.Method != "" {
		clauses = append(clauses, "method=?")
		args = append(args, f.Method)
	}
	if f.Status != "" {
		// Status is "pending", a class such as "4xx", or an exact code; the web handler validates it.
		low, high := 0, 0
		if strings.HasSuffix(f.Status, "xx") {
			low = int(f.Status[0]-'0') * 100
			high = low + 99
		} else if f.Status != "pending" {
			low, _ = strconv.Atoi(f.Status)
			high = low
		}
		clauses = append(clauses, "status BETWEEN ? AND ?")
		args = append(args, low, high)
	}
	const hostExpr = `host`
	urlExpr := `url`
	if f.Decode > 0 {
		urlExpr = fmt.Sprintf(`traffic_url_decode(%s,%d)`, urlExpr, f.Decode)
	}
	if f.Keyword != "" {
		clauses = append(clauses, `(`+hostExpr+` LIKE ? ESCAPE '\' OR `+urlExpr+` LIKE ? ESCAPE '\')`)
		pattern := "%" + escapeLike(f.Keyword) + "%"
		args = append(args, pattern, pattern)
	}
	for _, term := range excludeTerms(f.Exclude) {
		clauses = append(clauses, `NOT (COALESCE(`+hostExpr+`,'') LIKE ? ESCAPE '\' OR COALESCE(`+urlExpr+`,'') LIKE ? ESCAPE '\')`)
		pattern := "%" + escapeLike(term) + "%"
		args = append(args, pattern, pattern)
	}
	if f.Param != "" {
		// Parameter names are matched as typed in the stored URL, at the start of
		// the query or after a separator, with or without a value.
		raw := `url`
		name := escapeLike(f.Param)
		clauses = append(clauses, `(`+raw+` LIKE ? ESCAPE '\' OR `+raw+` LIKE ? ESCAPE '\' OR `+raw+` LIKE ? ESCAPE '\' OR `+raw+` LIKE ? ESCAPE '\' OR `+raw+` LIKE ? ESCAPE '\' OR `+raw+` LIKE ? ESCAPE '\')`)
		args = append(args, "%?"+name+"=%", "%&"+name+"=%", "%?"+name+"&%", "%&"+name+"&%", "%?"+name, "%&"+name)
	}
	if f.HideStatic {
		path := `lower(CASE WHEN instr(u,'?')>0 THEN substr(u,1,instr(u,'?')-1) ELSE u END)`
		var tests []string
		for _, extension := range staticExtensions {
			tests = append(tests, path+" LIKE '%."+extension+"'")
		}
		clauses = append(clauses, `NOT EXISTS (SELECT 1 FROM (SELECT COALESCE(entries.url,'') AS u) WHERE `+strings.Join(tests, " OR ")+`)`)
	}
	return strings.Join(clauses, " AND "), args
}

// excludeTerms splits the exclusion list on spaces and ASCII or full-width commas.
func excludeTerms(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '，' || unicode.IsSpace(r) })
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func readTUIStatus(dir string) (Stats, string) {
	var status Stats
	path := filepath.Join(dir, "status.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return status, "状态文件不可用，仍可浏览已保存请求"
	}
	if err = json.Unmarshal(b, &status); err != nil {
		return status, "状态文件格式错误，仍可浏览已保存请求"
	}
	if info, err := os.Stat(path); err == nil && status.State == "running" && time.Since(info.ModTime()) > 5*time.Second {
		status.State = "stale"
		if lock, err := os.Open(filepath.Join(dir, "capture.lock")); err == nil {
			defer lock.Close()
			if session.LockFile(lock, false) == nil {
				session.UnlockFile(lock)
				status.State = "interrupted"
				status.DrainState = "unverified"
				return status, "采集未正常结束，文件锁已释放，尾部数据及探针清理状态未知"
			}
		}
		return status, "采集心跳超过 5 秒未更新，请检查采集进程"
	}
	return status, ""
}

// loadTUISnapshot queries summaries in SQLite so bodies are only transferred for an opened detail.
func loadTUISnapshot(ctx context.Context, s *Store, filter tuiFilter, alertsOnly bool, page int, detailID string, anchor *tuiRow, limits ...int) (tuiSnapshot, error) {
	return loadTUISnapshotWithMeta(ctx, s, filter, alertsOnly, page, detailID, nil, anchor, limits...)
}

func loadTUISnapshotWithMeta(ctx context.Context, s *Store, filter tuiFilter, alertsOnly bool, page int, detailID string, prevMeta *tuiDetailMeta, anchor *tuiRow, limits ...int) (tuiSnapshot, error) {
	pageSize := 100
	if len(limits) > 0 && limits[0] > 0 {
		pageSize = min(limits[0], 500)
	}
	if s == nil {
		return tuiSnapshot{}, fmt.Errorf("会话未打开")
	}
	if !s.reader || s.db == nil {
		fresh, openErr := openStore(s.dir)
		if openErr != nil {
			return tuiSnapshot{}, openErr
		}
		defer fresh.db.Close()
		s = fresh
	}
	result := tuiSnapshot{Page: page}
	result.Stats, result.StatusWarning = readTUIStatus(s.dir)
	var reconstructed *Stats
	if s.analysis != nil {
		result.Stats.Alerts = s.analysis.Alerts
		if s.analysis.Reconstructed {
			result.Stats.Transactions = s.analysis.Transactions
		}
		reconstructed = s.analysis.Reconstruction
	}
	if statusInfo, statErr := os.Stat(filepath.Join(s.dir, "status.json")); statErr == nil {
		result.Stats.IntegrityWarnings = session.ComputeIntegrityWarnings(result.Stats, reconstructed, statusInfo.ModTime().UTC())
	} else if len(result.Stats.IntegrityWarnings) > 0 {
		result.Stats.IntegrityWarnings = session.ComputeIntegrityWarnings(result.Stats, reconstructed, time.Time{})
	}
	if s.analysisNote != "" {
		if result.StatusWarning != "" {
			result.StatusWarning += "；"
		}
		result.StatusWarning += s.analysisNote
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	where, args := filter.where(alertsOnly)
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM entries WHERE "+where, args...).Scan(&result.Count); err != nil {
		return result, err
	}
	maxPage := (max(result.Count, 1) - 1) / pageSize
	result.Page = max(0, min(page, maxPage))
	query := `SELECT id,time,client,method,host,url,status,incomplete,truncated,
 CASE severity WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE '' END,rule
 FROM entries WHERE ` + where + ` ORDER BY time DESC,id DESC LIMIT ? OFFSET ?`
	offset := result.Page * pageSize
	if anchor != nil && result.Page == page {
		newerArgs := append(append([]any{}, args...), anchor.Time, anchor.Time, anchor.ID)
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM entries WHERE "+where+" AND (time>? OR (time=? AND id>?))", newerArgs...).Scan(&result.Newer); err != nil {
			return result, err
		}
		query = strings.Replace(query, " ORDER BY time DESC,id DESC", " AND (time<? OR (time=? AND id<=?)) ORDER BY time DESC,id DESC", 1)
		args = append(args, anchor.Time, anchor.Time, anchor.ID)
		offset = 0
	}
	pageArgs := append(append([]any{}, args...), pageSize, offset)
	rows, err := tx.QueryContext(ctx, query, pageArgs...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var row tuiRow
		if err = rows.Scan(&row.ID, &row.Time, &row.Client, &row.Method, &row.Host, &row.URL, &row.Status, &row.Incomplete, &row.Truncated, &row.Severity, &row.Rule); err != nil {
			rows.Close()
			return result, err
		}
		result.Rows = append(result.Rows, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if anchor != nil && len(result.Rows) == 0 && result.Count > 0 {
		// Retention can remove the entire anchored tail while newer pages remain.
		if err := tx.Rollback(); err != nil {
			return result, err
		}
		return loadTUISnapshotWithMeta(ctx, s, filter, alertsOnly, result.Page, detailID, prevMeta, nil, limits...)
	}
	if detailID != "" {
		var meta tuiDetailMeta
		meta.ID = detailID
		err = tx.QueryRowContext(ctx, `SELECT status,incomplete,truncated,alert,alerts FROM entries WHERE id=?`, detailID).Scan(&meta.Status, &meta.Incomplete, &meta.Truncated, &meta.AlertCount, &meta.Alerts)
		if err == sql.ErrNoRows {
			result.DetailMissing = true
		} else if err != nil {
			return result, err
		} else {
			result.DetailMeta = &meta
			if prevMeta != nil && *prevMeta == meta {
				result.DetailUnchanged = true
			} else {
				var b []byte
				err = tx.QueryRowContext(ctx, "SELECT data FROM records WHERE id=?", detailID).Scan(&b)
				if err == sql.ErrNoRows {
					result.DetailMissing = true
				} else if err != nil {
					return result, err
				} else {
					var t Transaction
					if err = json.Unmarshal(b, &t); err != nil {
						return result, fmt.Errorf("读取请求详情: %w", err)
					}
					result.Detail = &t
				}
			}
		}
	}
	return result, tx.Commit()
}

// tuiRuleAgg and tuiSourceAgg summarize alerting requests; Hits counts requests.
type tuiRuleAgg struct {
	Rule, Severity, Last, Match string
	Hits, Sources               int
}
type tuiSourceAgg struct {
	Client, First, Last string
	Hits                int
	Rules               []string
}
type tuiSummary struct {
	// Levels counts alerting requests by their highest matching severity rank.
	Levels        [4]int
	AlertRequests int
	Rules         []tuiRuleAgg
	Sources       []tuiSourceAgg
	SourcesCapped bool
	Recent        []tuiRow
}

const (
	tuiSourceLimit = 200
	tuiRuleLimit   = 500
	tuiRecentLimit = 20
)

type tuiSummaryCacheKey struct {
	dir    string
	filter tuiFilter
}

type tuiSummaryCacheEntry struct {
	revision string
	data     *tuiSummary
}

var (
	tuiSummaryCacheMu sync.Mutex
	tuiSummaryCache   = map[tuiSummaryCacheKey]tuiSummaryCacheEntry{}
)

// loadTUISummary aggregates the alerts of matching requests inside SQLite. Rule
// and severity conditions also restrict which alerts of a request are counted.
func loadTUISummary(ctx context.Context, s *Store, filter tuiFilter) (*tuiSummary, error) {
	if s == nil {
		return nil, fmt.Errorf("会话未打开")
	}
	if !s.reader || s.db == nil {
		fresh, openErr := openStore(s.dir)
		if openErr != nil {
			return nil, openErr
		}
		defer fresh.db.Close()
		s = fresh
	}
	status, _ := readTUIStatus(s.dir)
	finished := status.State != "" && status.State != "running" && status.State != "starting" && status.State != "stale"
	var revision string
	cacheKey := tuiSummaryCacheKey{dir: s.dir, filter: filter}
	if finished {
		revision = summaryRevision(s)
		if revision != "" {
			tuiSummaryCacheMu.Lock()
			entry, ok := tuiSummaryCache[cacheKey]
			tuiSummaryCacheMu.Unlock()
			if ok && entry.revision == revision {
				return entry.data, nil
			}
		}
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	where, args := filter.where(true)
	minRank := severityRank(filter.Severity)
	alertCond := sqlSeverityRank + ">=?"
	alertArgs := []any{minRank}
	if filter.Rule != "" {
		alertCond = "json_extract(a.value,'$.rule')=? AND " + alertCond
		alertArgs = append([]any{filter.Rule}, alertArgs...)
	}
	joinedArgs := append(append([]any{}, args...), alertArgs...)

	result := &tuiSummary{}

	// 1. Levels & total alerting requests.
	var low, medium, high, other int
	if filter.Rule == "" {
		err = tx.QueryRowContext(ctx, `SELECT count(*),
 COALESCE(sum(CASE WHEN severity=1 THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN severity=2 THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN severity=3 THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN severity<1 OR severity>3 THEN 1 ELSE 0 END),0)
 FROM entries WHERE `+where, args...).Scan(&result.AlertRequests, &low, &medium, &high, &other)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT count(*),
 COALESCE(sum(CASE WHEN best=1 THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN best=2 THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN best=3 THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN best<1 OR best>3 THEN 1 ELSE 0 END),0)
 FROM (
  SELECT max(`+sqlSeverityRank+`) AS best
  FROM entries, json_each(entries.alerts) a
  WHERE `+where+` AND `+alertCond+`
  GROUP BY entries.id
 )`, joinedArgs...).Scan(&result.AlertRequests, &low, &medium, &high, &other)
	}
	if err != nil {
		return nil, err
	}
	result.Levels = [4]int{other, low, medium, high}

	// 2. Per-rule aggregation with newest match (bounded by tuiRuleLimit).
	severityNames := [...]string{"", "low", "medium", "high"}
	ruleRows, err := tx.QueryContext(ctx, `SELECT rule, max(rank) AS max_rank, count(DISTINCT id) AS hits, count(DISTINCT src) AS sources, max(at) AS last_at,
 COALESCE(max(CASE WHEN rn=1 THEN match_text END),'')
 FROM (
  SELECT
   COALESCE(json_extract(a.value,'$.rule'),'') AS rule,
   `+sqlSeverityRank+` AS rank,
   COALESCE(json_extract(a.value,'$.match'),'') AS match_text,
   entries.id AS id,
   entries.time AS at,
   `+sqlClientHost+` AS src,
   ROW_NUMBER() OVER (PARTITION BY COALESCE(json_extract(a.value,'$.rule'),'') ORDER BY entries.time DESC, entries.id DESC, a.key ASC) AS rn
  FROM entries, json_each(entries.alerts) a
  WHERE `+where+` AND `+alertCond+`
 )
 GROUP BY rule
 ORDER BY max_rank DESC, hits DESC, rule ASC
 LIMIT ?`, append(append([]any{}, joinedArgs...), tuiRuleLimit)...)
	if err != nil {
		return nil, err
	}
	for ruleRows.Next() {
		var agg tuiRuleAgg
		var rank int
		if err = ruleRows.Scan(&agg.Rule, &rank, &agg.Hits, &agg.Sources, &agg.Last, &agg.Match); err != nil {
			ruleRows.Close()
			return nil, err
		}
		if rank >= 0 && rank < len(severityNames) {
			agg.Severity = severityNames[rank]
		}
		result.Rules = append(result.Rules, agg)
	}
	err = ruleRows.Err()
	ruleRows.Close()
	if err != nil {
		return nil, err
	}

	// 3. Per-source aggregation (bounded by tuiSourceLimit+1 to detect capping).
	srcRows, err := tx.QueryContext(ctx, `SELECT src, count(DISTINCT id) AS hits, min(at), max(at), json_group_array(DISTINCT rule)
 FROM (
  SELECT
   `+sqlClientHost+` AS src,
   entries.id AS id,
   entries.time AS at,
   COALESCE(json_extract(a.value,'$.rule'),'') AS rule
  FROM entries, json_each(entries.alerts) a
  WHERE `+where+` AND `+alertCond+`
 )
 GROUP BY src
 ORDER BY hits DESC, max(at) DESC, src ASC
 LIMIT ?`, append(append([]any{}, joinedArgs...), tuiSourceLimit+1)...)
	if err != nil {
		return nil, err
	}
	for srcRows.Next() {
		var agg tuiSourceAgg
		var rawRules []byte
		if err = srcRows.Scan(&agg.Client, &agg.Hits, &agg.First, &agg.Last, &rawRules); err != nil {
			srcRows.Close()
			return nil, err
		}
		if len(rawRules) > 0 {
			_ = json.Unmarshal(rawRules, &agg.Rules)
			sort.Strings(agg.Rules)
		}
		result.Sources = append(result.Sources, agg)
	}
	err = srcRows.Err()
	srcRows.Close()
	if err != nil {
		return nil, err
	}
	if len(result.Sources) > tuiSourceLimit {
		result.Sources, result.SourcesCapped = result.Sources[:tuiSourceLimit], true
	}

	// 4. Recent high-severity alerting requests (bounded by tuiRecentLimit).
	highCond := `json_extract(a.value,'$.severity')='high'`
	var highArgs []any
	if filter.Rule != "" {
		highCond = `json_extract(a.value,'$.rule')=? AND ` + highCond
		highArgs = append(highArgs, filter.Rule)
	}
	recentArgs := append(append([]any{}, highArgs...), args...)
	recentArgs = append(recentArgs, highArgs...)
	recentArgs = append(recentArgs, tuiRecentLimit)
	recentRows, err := tx.QueryContext(ctx, `SELECT entries.id,entries.time,entries.client,entries.method,entries.host,entries.url,
 COALESCE((SELECT json_extract(a.value,'$.rule') FROM json_each(entries.alerts) a WHERE `+highCond+` ORDER BY a.key LIMIT 1),'')
 FROM entries
 WHERE `+where+` AND EXISTS (SELECT 1 FROM json_each(entries.alerts) a WHERE `+highCond+`)
 ORDER BY entries.time DESC, entries.id DESC
 LIMIT ?`, recentArgs...)
	if err != nil {
		return nil, err
	}
	for recentRows.Next() {
		var row tuiRow
		if err = recentRows.Scan(&row.ID, &row.Time, &row.Client, &row.Method, &row.Host, &row.URL, &row.Rule); err != nil {
			recentRows.Close()
			return nil, err
		}
		row.Severity = "high"
		result.Recent = append(result.Recent, row)
	}
	err = recentRows.Err()
	recentRows.Close()
	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if finished && revision != "" {
		tuiSummaryCacheMu.Lock()
		if len(tuiSummaryCache) > 64 {
			tuiSummaryCache = map[tuiSummaryCacheKey]tuiSummaryCacheEntry{}
		}
		tuiSummaryCache[cacheKey] = tuiSummaryCacheEntry{revision: revision, data: result}
		tuiSummaryCacheMu.Unlock()
	}
	return result, nil
}
