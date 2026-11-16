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
	"strings"
	"time"
)

// tuiFilter applies to persisted transactions, including records written by v1.
type tuiFilter struct {
	Client, Rule, Severity, Since, Keyword, Service string
}

type tuiRow struct {
	ID, Time, Client, Method, Host, URL, Severity, Rule string
	Status                                              int
	Incomplete, Truncated                               bool
}

type tuiSnapshot struct {
	Rows          []tuiRow
	Count         int
	Page          int
	Stats         Stats
	StatusWarning string
	Detail        *Transaction
	DetailMissing bool
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
	if alertsOnly {
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
	if f.Rule != "" || f.Severity != "" {
		clauses = append(clauses, `EXISTS (SELECT 1 FROM json_each(CAST(requests.data AS TEXT), '$.alerts') a WHERE (?='' OR json_extract(a.value,'$.rule')=?) AND `+sqlSeverityRank+`>=?)`)
		args = append(args, f.Rule, f.Rule, severityRank(f.Severity))
	}
	if f.Service != "" {
		clauses = append(clauses, "json_extract(CAST(data AS TEXT),'$.service')=?")
		args = append(args, f.Service)
	}
	if f.Keyword != "" {
		clauses = append(clauses, `(json_extract(CAST(data AS TEXT),'$.host') LIKE ? ESCAPE '\' OR json_extract(CAST(data AS TEXT),'$.url') LIKE ? ESCAPE '\')`)
		pattern := "%" + escapeLike(f.Keyword) + "%"
		args = append(args, pattern, pattern)
	}
	return strings.Join(clauses, " AND "), args
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
		return status, "采集心跳超过 5 秒未更新，请检查采集进程"
	}
	return status, ""
}

// Query summaries in SQLite so bodies are only transferred for an opened detail.
func loadTUISnapshot(ctx context.Context, s *Store, filter tuiFilter, alertsOnly bool, page int, detailID string, anchor *tuiRow) (tuiSnapshot, error) {
	result := tuiSnapshot{Page: page}
	result.Stats, result.StatusWarning = readTUIStatus(s.dir)
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	where, args := filter.where(alertsOnly)
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM requests WHERE "+where, args...).Scan(&result.Count); err != nil {
		return result, err
	}
	maxPage := (max(result.Count, 1) - 1) / 100
	result.Page = max(0, min(page, maxPage))
	query := `SELECT id,time,client,
 COALESCE(json_extract(CAST(data AS TEXT),'$.method'),''),
 COALESCE(json_extract(CAST(data AS TEXT),'$.host'),''),
 COALESCE(json_extract(CAST(data AS TEXT),'$.url'),''),
 COALESCE(json_extract(CAST(data AS TEXT),'$.status'),0),
 COALESCE(json_extract(CAST(data AS TEXT),'$.incomplete'),0),
 COALESCE(json_extract(CAST(data AS TEXT),'$.truncated'),0),
 CASE COALESCE((SELECT max(` + sqlSeverityRank + `) FROM json_each(CAST(requests.data AS TEXT),'$.alerts') a),0)
 WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE '' END,
 COALESCE((SELECT json_extract(a.value,'$.rule') FROM json_each(CAST(requests.data AS TEXT),'$.alerts') a ORDER BY ` + sqlSeverityRank + ` DESC LIMIT 1),'')
 FROM requests WHERE ` + where + ` ORDER BY time DESC,id DESC LIMIT 100 OFFSET ?`
	offset := result.Page * 100
	if anchor != nil && result.Page == page {
		newerArgs := append(append([]any{}, args...), anchor.Time, anchor.Time, anchor.ID)
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM requests WHERE "+where+" AND (time>? OR (time=? AND id>?))", newerArgs...).Scan(&result.Newer); err != nil {
			return result, err
		}
		query = strings.Replace(query, " ORDER BY time DESC,id DESC", " AND (time<? OR (time=? AND id<=?)) ORDER BY time DESC,id DESC", 1)
		args = append(args, anchor.Time, anchor.Time, anchor.ID)
		offset = 0
	}
	pageArgs := append(append([]any{}, args...), offset)
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
		return loadTUISnapshot(ctx, s, filter, alertsOnly, result.Page, detailID, nil)
	}
	if detailID != "" {
		var b []byte
		err = tx.QueryRowContext(ctx, "SELECT data FROM requests WHERE id=?", detailID).Scan(&b)
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

const tuiSourceLimit = 200

// loadTUISummary aggregates the alerts of matching requests in one scan. Rule and
// severity conditions also restrict which alerts of a request are counted.
func loadTUISummary(ctx context.Context, s *Store, filter tuiFilter) (*tuiSummary, error) {
	where, args := filter.where(true)
	// One json_extract with several paths parses each record once.
	rows, err := s.db.QueryContext(ctx, `SELECT id, time, client, json_extract(CAST(data AS TEXT),'$.alerts','$.method','$.host','$.url')
 FROM requests WHERE `+where+` ORDER BY time DESC, id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type ruleState struct {
		agg     tuiRuleAgg
		sources map[string]bool
	}
	type sourceState struct {
		agg   tuiSourceAgg
		rules map[string]bool
	}
	result := &tuiSummary{}
	byRule := map[string]*ruleState{}
	bySource := map[string]*sourceState{}
	minRank := severityRank(filter.Severity)
	for rows.Next() {
		var id, at, client string
		var fields []byte
		if err = rows.Scan(&id, &at, &client, &fields); err != nil {
			return nil, err
		}
		var parts []json.RawMessage
		var alerts []Alert
		var method, host, url string
		if json.Unmarshal(fields, &parts) != nil || len(parts) != 4 {
			continue
		}
		json.Unmarshal(parts[0], &alerts)
		json.Unmarshal(parts[1], &method)
		json.Unmarshal(parts[2], &host)
		json.Unmarshal(parts[3], &url)
		best, highRule, seen := 0, "", map[string]bool{}
		source := tuiClientHost(client)
		for _, a := range alerts {
			rank := severityRank(a.Severity)
			if (filter.Rule != "" && a.Rule != filter.Rule) || rank < minRank {
				continue
			}
			best = max(best, rank)
			if rank == 3 && highRule == "" {
				highRule = a.Rule
			}
			// Rows arrive newest first, so the first sighting holds the latest match.
			r := byRule[a.Rule]
			if r == nil {
				r = &ruleState{agg: tuiRuleAgg{Rule: a.Rule, Last: at, Match: a.Match}, sources: map[string]bool{}}
				byRule[a.Rule] = r
			}
			if rank > severityRank(r.agg.Severity) {
				r.agg.Severity = a.Severity
			}
			if !seen[a.Rule] {
				seen[a.Rule] = true
				r.agg.Hits++
				r.sources[source] = true
			}
		}
		if len(seen) == 0 {
			continue
		}
		result.Levels[best]++
		result.AlertRequests++
		src := bySource[source]
		if src == nil {
			src = &sourceState{agg: tuiSourceAgg{Client: source, Last: at}, rules: map[string]bool{}}
			bySource[source] = src
		}
		src.agg.Hits++
		src.agg.First = at
		for rule := range seen {
			src.rules[rule] = true
		}
		if highRule != "" && len(result.Recent) < 20 {
			result.Recent = append(result.Recent, tuiRow{ID: id, Time: at, Client: client, Method: method, Host: host, URL: url, Rule: highRule, Severity: "high"})
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for _, r := range byRule {
		r.agg.Sources = len(r.sources)
		result.Rules = append(result.Rules, r.agg)
	}
	sort.Slice(result.Rules, func(i, j int) bool {
		a, b := result.Rules[i], result.Rules[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.Hits != b.Hits {
			return a.Hits > b.Hits
		}
		return a.Rule < b.Rule
	})
	for _, src := range bySource {
		for rule := range src.rules {
			src.agg.Rules = append(src.agg.Rules, rule)
		}
		sort.Strings(src.agg.Rules)
		result.Sources = append(result.Sources, src.agg)
	}
	sort.Slice(result.Sources, func(i, j int) bool {
		a, b := result.Sources[i], result.Sources[j]
		if a.Hits != b.Hits {
			return a.Hits > b.Hits
		}
		if a.Last != b.Last {
			return a.Last > b.Last
		}
		return a.Client < b.Client
	})
	if len(result.Sources) > tuiSourceLimit {
		result.Sources, result.SourcesCapped = result.Sources[:tuiSourceLimit], true
	}
	return result, nil
}
