package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type webBucket struct {
	Time     string `json:"t"`
	Requests int    `json:"requests"`
	Alerts   int    `json:"alerts,omitempty"`
}

type webCount struct {
	Name     string `json:"name"`
	Severity string `json:"severity,omitempty"`
	Count    int    `json:"count"`
	Alerts   int    `json:"alerts,omitempty"`
}

// Index timestamps are fixed-width UTC strings, so a prefix of the time column
// is a bucket key that SQLite can group without parsing every record body.
var webGranularities = []struct {
	Seconds, Prefix int
	Suffix          string
}{
	{1, 19, "Z"}, {10, 18, "0Z"}, {60, 16, ":00Z"}, {600, 15, "0:00Z"}, {3600, 13, ":00:00Z"}, {86400, 10, "T00:00:00Z"},
}

const webTimelineBuckets = 120

func (w *webServer) handleTimeline(rw http.ResponseWriter, r *http.Request) {
	filter, get, err := webFilter(r)
	if err != nil {
		webError(rw, http.StatusBadRequest, err)
		return
	}
	s := w.sessionStore(rw, r)
	if s == nil {
		return
	}
	defer s.db.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	where, args := filter.where(get("alerts") == "1")
	var first, last sql.NullString
	var total int
	if err = s.db.QueryRowContext(ctx, "SELECT min(time),max(time),count(*) FROM entries WHERE "+where, args...).Scan(&first, &last, &total); err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	result := map[string]any{"total": total, "granularity": 1, "buckets": []webBucket{}}
	if total == 0 {
		webJSON(rw, http.StatusOK, result)
		return
	}
	start, startErr := time.Parse(indexTimeFormat, first.String)
	end, endErr := time.Parse(indexTimeFormat, last.String)
	if startErr != nil || endErr != nil {
		webError(rw, http.StatusInternalServerError, errors.New("索引时间格式无法识别"))
		return
	}
	granularity := webGranularities[len(webGranularities)-1]
	for _, candidate := range webGranularities {
		if int(end.Sub(start).Seconds())/candidate.Seconds < webTimelineBuckets {
			granularity = candidate
			break
		}
	}
	rows, err := s.db.QueryContext(ctx, "SELECT substr(time,1,?),count(*),COALESCE(sum(alert>0),0) FROM entries WHERE "+where+" GROUP BY 1 ORDER BY 1", append([]any{granularity.Prefix}, args...)...)
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()
	buckets := []webBucket{}
	for rows.Next() {
		var bucket webBucket
		if err = rows.Scan(&bucket.Time, &bucket.Requests, &bucket.Alerts); err != nil {
			webError(rw, http.StatusInternalServerError, err)
			return
		}
		bucket.Time += granularity.Suffix
		buckets = append(buckets, bucket)
	}
	if err = rows.Err(); err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	result["granularity"], result["buckets"] = granularity.Seconds, buckets
	result["first"], result["last"] = start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano)
	webJSON(rw, http.StatusOK, result)
}

func webCounts(ctx context.Context, db *sql.DB, query string, args []any, scan func(*sql.Rows, *webCount) error) ([]webCount, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []webCount{}
	for rows.Next() {
		var item webCount
		if err = scan(rows, &item); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func summaryRevision(s *Store) string {
	signature, err := sourceSignature(s.dir)
	if err != nil {
		return ""
	}
	if s.analysis != nil {
		signature += fmt.Sprintf("|%s|%s", s.analysis.Completed.Format(time.RFC3339Nano), s.analysis.RulesSHA256)
	}
	if info, err := os.Stat(filepath.Join(s.dir, "status.json")); err == nil {
		signature += fmt.Sprintf("|%d:%d", info.Size(), info.ModTime().UnixNano())
	}
	return signature
}

func (w *webServer) handleSummary(rw http.ResponseWriter, r *http.Request) {
	filter, _, err := webFilter(r)
	if err != nil {
		webError(rw, http.StatusBadRequest, err)
		return
	}
	s := w.sessionStore(rw, r)
	if s == nil {
		return
	}
	defer s.db.Close()
	// Finished sessions cannot change until their index or analysis file does.
	// Cache those summaries; running captures are re-scanned on every request.
	status, _ := readTUIStatus(s.dir)
	finished := status.State != "" && status.State != "running" && status.State != "starting" && status.State != "stale"
	revision := summaryRevision(s)
	key := s.dir + "|" + r.URL.RawQuery
	if finished && revision != "" {
		w.summaryMu.Lock()
		entry, ok := w.summaries[key]
		w.summaryMu.Unlock()
		if ok && entry.revision == revision {
			webJSON(rw, http.StatusOK, entry.data)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	where, args := filter.where(false)
	result := map[string]any{}
	var total, alerted int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(alert>0),0) FROM entries WHERE "+where, args...).Scan(&total, &alerted); err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	result["total"], result["alerted"] = total, alerted

	// The port is stripped so one source address aggregates across connections.
	clients, err := webCounts(ctx, s.db, `SELECT rtrim(rtrim(client,'0123456789'),':'),count(*),COALESCE(sum(alert>0),0) FROM entries WHERE `+where+` GROUP BY 1 ORDER BY 3 DESC,2 DESC,1 LIMIT 10`, args,
		func(rows *sql.Rows, item *webCount) error { return rows.Scan(&item.Name, &item.Count, &item.Alerts) })
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	result["clients"] = clients

	// Rule and severity breakdowns only parse the records that carry alerts.
	rules, err := webCounts(ctx, s.db, `SELECT COALESCE(json_extract(hit.value,'$.rule'),''),COALESCE(json_extract(hit.value,'$.severity'),''),count(DISTINCT entries.id) FROM entries, json_each(entries.alerts) hit WHERE entries.alert>0 AND `+where+` GROUP BY 1,2 ORDER BY 3 DESC,1 LIMIT 10`, args,
		func(rows *sql.Rows, item *webCount) error { return rows.Scan(&item.Name, &item.Severity, &item.Count) })
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	result["rules"] = rules
	severities, err := webCounts(ctx, s.db, `SELECT severity,count(*) FROM entries WHERE alert>0 AND `+where+` GROUP BY severity`, args,
		func(rows *sql.Rows, item *webCount) error {
			var level int
			if err := rows.Scan(&level, &item.Count); err != nil {
				return err
			}
			item.Name = []string{"", "low", "medium", "high"}[level]
			return nil
		})
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	result["severities"] = severities

	// Legacy layouts compute status from every record body. That scan can be
	// expensive, so it keeps a short budget and is omitted when it overruns.
	statusCtx, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
	statuses, err := webCounts(statusCtx, s.db, `SELECT status/100,count(*) FROM entries WHERE `+where+` GROUP BY 1 ORDER BY 1`, args,
		func(rows *sql.Rows, item *webCount) error {
			var class int
			if err := rows.Scan(&class, &item.Count); err != nil {
				return err
			}
			item.Name = "other"
			if class == 0 {
				item.Name = "pending"
			} else if class >= 1 && class <= 5 {
				item.Name = string(rune('0'+class)) + "xx"
			}
			return nil
		})
	stop()
	if err == nil {
		result["statuses"] = statuses
	} else if ctx.Err() != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	if finished && revision != "" {
		w.summaryMu.Lock()
		if len(w.summaries) > 128 {
			w.summaries = map[string]summaryCacheEntry{}
		}
		w.summaries[key] = summaryCacheEntry{revision: revision, data: result}
		w.summaryMu.Unlock()
	}
	webJSON(rw, http.StatusOK, result)
}
