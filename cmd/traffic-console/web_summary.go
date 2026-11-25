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

// sessionTimeline buckets matching requests by time; Alerts counts alerting requests.
type sessionTimeline struct {
	Total       int         `json:"total"`
	Granularity int         `json:"granularity"`
	Buckets     []webBucket `json:"buckets"`
	First       string      `json:"first,omitempty"`
	Last        string      `json:"last,omitempty"`
}

func querySessionTimeline(ctx context.Context, db *sql.DB, filter tuiFilter, alertsOnly bool) (sessionTimeline, error) {
	where, args := filter.where(alertsOnly)
	var first, last sql.NullString
	result := sessionTimeline{Granularity: 1, Buckets: []webBucket{}}
	if err := db.QueryRowContext(ctx, "SELECT min(time),max(time),count(*) FROM entries WHERE "+where, args...).Scan(&first, &last, &result.Total); err != nil {
		return result, err
	}
	if result.Total == 0 {
		return result, nil
	}
	start, startErr := time.Parse(indexTimeFormat, first.String)
	end, endErr := time.Parse(indexTimeFormat, last.String)
	if startErr != nil || endErr != nil {
		return result, errors.New("索引时间格式无法识别")
	}
	granularity := webGranularities[len(webGranularities)-1]
	for _, candidate := range webGranularities {
		if int(end.Sub(start).Seconds())/candidate.Seconds < webTimelineBuckets {
			granularity = candidate
			break
		}
	}
	rows, err := db.QueryContext(ctx, "SELECT substr(time,1,?),count(*),COALESCE(sum(alert>0),0) FROM entries WHERE "+where+" GROUP BY 1 ORDER BY 1", append([]any{granularity.Prefix}, args...)...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	buckets := []webBucket{}
	for rows.Next() {
		var bucket webBucket
		if err = rows.Scan(&bucket.Time, &bucket.Requests, &bucket.Alerts); err != nil {
			return result, err
		}
		bucket.Time += granularity.Suffix
		buckets = append(buckets, bucket)
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	result.Granularity, result.Buckets = granularity.Seconds, buckets
	result.First, result.Last = start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano)
	return result, nil
}

func (w *webServer) handleTimeline(rw http.ResponseWriter, r *http.Request) {
	filter, get, err := webFilter(r)
	if err != nil {
		webError(rw, http.StatusBadRequest, err)
		return
	}
	s, release := w.sessionStore(rw, r)
	if s == nil {
		return
	}
	defer release()
	status, _ := readTUIStatus(s.dir)
	finished := status.State != "" && status.State != "running" && status.State != "starting" && status.State != "stale"
	revision := summaryRevision(s)
	key := s.dir + "|" + r.URL.RawQuery
	if finished && revision != "" {
		w.timelineMu.Lock()
		entry, ok := w.timelines[key]
		w.timelineMu.Unlock()
		if ok && entry.revision == revision {
			webJSON(rw, http.StatusOK, entry.data)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	result, err := querySessionTimeline(ctx, s.db, filter, get("alerts") == "1")
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	if finished && revision != "" {
		w.timelineMu.Lock()
		if len(w.timelines) > 128 {
			w.timelines = map[string]timelineCacheEntry{}
		}
		w.timelines[key] = timelineCacheEntry{revision: revision, data: result}
		w.timelineMu.Unlock()
	}
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
	s, release := w.sessionStore(rw, r)
	if s == nil {
		return
	}
	defer release()
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
	summary, err := querySessionSummary(ctx, s.db, filter)
	if err != nil {
		webError(rw, http.StatusInternalServerError, err)
		return
	}
	result := map[string]any{"total": summary.Total, "alerted": summary.Alerted, "clients": summary.Clients, "rules": summary.Rules, "severities": summary.Severities}
	if summary.Statuses != nil {
		result["statuses"] = summary.Statuses
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

// sessionSummary is the overview breakdown shared by the web page and the TUI.
// Statuses is nil when the status scan overran its budget.
type sessionSummary struct {
	Total, Alerted                       int
	Clients, Rules, Severities, Statuses []webCount
}

func querySessionSummary(ctx context.Context, db *sql.DB, filter tuiFilter) (sessionSummary, error) {
	where, args := filter.where(false)
	var result sessionSummary
	var low, medium, high, other int
	if err := db.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(alert>0),0),
 COALESCE(sum(CASE WHEN alert>0 AND severity=1 THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN alert>0 AND severity=2 THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN alert>0 AND severity=3 THEN 1 ELSE 0 END),0),
 COALESCE(sum(CASE WHEN alert>0 AND (severity<1 OR severity>3) THEN 1 ELSE 0 END),0)
 FROM entries WHERE `+where, args...).Scan(&result.Total, &result.Alerted, &low, &medium, &high, &other); err != nil {
		return result, err
	}
	result.Severities = []webCount{}
	if other > 0 {
		result.Severities = append(result.Severities, webCount{Name: "", Count: other})
	}
	if low > 0 {
		result.Severities = append(result.Severities, webCount{Name: "low", Count: low})
	}
	if medium > 0 {
		result.Severities = append(result.Severities, webCount{Name: "medium", Count: medium})
	}
	if high > 0 {
		result.Severities = append(result.Severities, webCount{Name: "high", Count: high})
	}
	var err error
	// The port is stripped so one source address aggregates across connections,
	// without mangling portless IPv4/IPv6 addresses.
	const clientHostExpr = `CASE WHEN substr(client,1,1)='[' AND instr(client,']:')>0 THEN substr(client,2,instr(client,']:')-2) WHEN instr(client,':')>0 AND instr(substr(client,instr(client,':')+1),':')=0 THEN substr(client,1,instr(client,':')-1) ELSE client END`
	result.Clients, err = webCounts(ctx, db, `SELECT `+clientHostExpr+`,count(*),COALESCE(sum(alert>0),0) FROM entries WHERE `+where+` GROUP BY 1 ORDER BY 3 DESC,2 DESC,1 LIMIT 10`, args,
		func(rows *sql.Rows, item *webCount) error { return rows.Scan(&item.Name, &item.Count, &item.Alerts) })
	if err != nil {
		return result, err
	}
	// Rule breakdowns only parse the records that carry alerts.
	result.Rules, err = webCounts(ctx, db, `SELECT COALESCE(json_extract(hit.value,'$.rule'),''),COALESCE(json_extract(hit.value,'$.severity'),''),count(DISTINCT entries.id) FROM entries, json_each(entries.alerts) hit WHERE entries.alert>0 AND `+where+` GROUP BY 1,2 ORDER BY 3 DESC,1 LIMIT 10`, args,
		func(rows *sql.Rows, item *webCount) error { return rows.Scan(&item.Name, &item.Severity, &item.Count) })
	if err != nil {
		return result, err
	}
	// Legacy layouts compute status from every record body. That scan can be
	// expensive, so it keeps a short budget and is omitted when it overruns.
	statusCtx, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
	statuses, err := webCounts(statusCtx, db, `SELECT status/100,count(*) FROM entries WHERE `+where+` GROUP BY 1 ORDER BY 1`, args,
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
		result.Statuses = statuses
	} else if ctx.Err() != nil {
		return result, err
	}
	return result, nil
}
