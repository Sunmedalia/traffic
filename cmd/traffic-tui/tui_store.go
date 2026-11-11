package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// tuiFilter applies to persisted transactions, including records written by v1.
type tuiFilter struct {
	Client, Rule, Severity, Since, Keyword string
}

type tuiRow struct {
	ID, Time, Client, Method, Host, URL, Severity string
	Status                                        int
	Incomplete, Truncated                         bool
}

type tuiSnapshot struct {
	Rows          []tuiRow
	Count         int
	Page          int
	Stats         Stats
	StatusWarning string
	Detail        *Transaction
	DetailMissing bool
}

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
		clauses = append(clauses, `EXISTS (SELECT 1 FROM json_each(CAST(requests.data AS TEXT), '$.alerts') a WHERE (?='' OR json_extract(a.value,'$.rule')=?) AND (?='' OR json_extract(a.value,'$.severity')=?))`)
		args = append(args, f.Rule, f.Rule, f.Severity, f.Severity)
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
 CASE COALESCE((SELECT max(CASE json_extract(a.value,'$.severity') WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) FROM json_each(CAST(requests.data AS TEXT),'$.alerts') a),0)
 WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE '' END
 FROM requests WHERE ` + where + ` ORDER BY time DESC,id DESC LIMIT 100 OFFSET ?`
	offset := result.Page * 100
	if anchor != nil && result.Page == page {
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
		if err = rows.Scan(&row.ID, &row.Time, &row.Client, &row.Method, &row.Host, &row.URL, &row.Status, &row.Incomplete, &row.Truncated, &row.Severity); err != nil {
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
