package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/Sunmedalia/traffic/internal/replay"
	"github.com/Sunmedalia/traffic/internal/session"
)

// Engine 5 adds the entries table; earlier generations remain readable.
const analysisEngineVersion = 5

type analysisReport struct {
	IntegrityWarnings []string      `json:"integrity_warnings,omitempty"`
	Reconstructed     bool          `json:"reconstructed"`
	RequestLimit      int           `json:"request_limit"`
	ResponseLimit     int           `json:"response_limit"`
	Reconstruction    *Stats        `json:"reconstruction,omitempty"`
	EngineVersion     int           `json:"engine_version"`
	Completed         time.Time     `json:"completed"`
	Transactions      uint64        `json:"transactions"`
	Alerts            uint64        `json:"alerts"`
	RulesSHA256       string        `json:"rules_sha256"`
	Rules             []Rule        `json:"rules"`
	ScanWindow        time.Duration `json:"scan_window_ns"`
	ScanPaths         int           `json:"scan_paths"`
	Source            string        `json:"source_signature"`
	Delivery          *Stats        `json:"delivery,omitempty"`
	// ScanSkipped counts transactions SCAN-001 could not track because the
	// client or per-client path limit was reached. Scans among them can go
	// unreported.
	ScanSkipped *scanSkipped `json:"scan_skipped,omitempty"`
}

func sessionIntegrityWarnings(dir string, reconstructed *Stats) []string {
	statusPath := filepath.Join(dir, "status.json")
	b, err := os.ReadFile(statusPath)
	if err != nil {
		return nil
	}
	var capture Stats
	if json.Unmarshal(b, &capture) != nil {
		return nil
	}
	var modTime time.Time
	if info, err := os.Stat(statusPath); err == nil {
		modTime = info.ModTime().UTC()
	}
	return session.ComputeIntegrityWarnings(capture, reconstructed, modTime)
}

// A cheap freshness check keeps opening large sessions independent of body size.
// Copying or changing the source index can invalidate results; analyze rebuilds them.
func sourceSignature(dir string) (string, error) {
	var parts []string
	names := []string{"index.sqlite", "index.sqlite-wal"}
	if rawSession(dir) {
		names = []string{"manifest.json"}
		files, err := session.PacketFiles(dir)
		if err != nil {
			return "", err
		}
		for _, file := range files {
			name, err := filepath.Rel(dir, file)
			if err != nil {
				return "", err
			}
			names = append(names, name)
		}
		if _, err := os.Stat(filepath.Join(dir, "tls", "stream.jsonl")); err == nil {
			names = append(names, filepath.Join("tls", "stream.jsonl"))
		} else if !os.IsNotExist(err) {
			return "", err
		}
		sort.Strings(names)
	}
	for _, name := range names {
		info, err := os.Stat(filepath.Join(dir, name))
		if os.IsNotExist(err) && strings.HasSuffix(name, "-wal") {
			continue
		}
		if err != nil {
			return "", err
		}
		if strings.HasSuffix(name, "-wal") && info.Size() == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%d", name, info.Size(), info.ModTime().UnixNano()))
	}
	return strings.Join(parts, "/"), nil
}

func analysisURL(path, mode string) string {
	absolute, _ := filepath.Abs(path)
	path = filepath.ToSlash(absolute)
	if runtime.GOOS == "windows" {
		path = "/" + path
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", mode)
	q.Set("_busy_timeout", "5000")
	if mode == "ro" {
		q.Set("immutable", "1")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func openAnalysisDB(dir string) (*sql.DB, error) {
	path, err := analysisDatabasePath(dir)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(index.Driver, analysisURL(path, "ro"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// openAnalysisBuild prepares an unpublished generation. A failed build is
// discarded and publication syncs the file once, so per-transaction journaling
// and fsync would only slow the build down.
func openAnalysisBuild(path string) (*sql.DB, error) {
	db, err := sql.Open(index.Driver, analysisURL(path, "rw"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF;
CREATE TABLE results(id TEXT PRIMARY KEY, alerts TEXT NOT NULL);
CREATE TABLE metadata(id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);
` + entriesTable); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Analysis reads capture evidence through a read-only connection and publishes
// a complete replacement result set in one SQLite transaction. Failure retains
// the previous results; neither bodies nor capture status are rewritten.
func analyzeSession(ctx context.Context, dir, webhookURL string) (analysisReport, error) {
	return analyzeSessionRules(ctx, dir, webhookURL, rules, scanWindow, scanThreshold)
}

func analyzeSessionRules(ctx context.Context, dir, webhookURL string, rs []Rule, window time.Duration, paths int) (analysisReport, error) {
	return analyzeConfigured(ctx, dir, webhookURL, rs, window, paths, replay.Options{RequestLimit: requestLimit, ResponseLimit: responseLimit})
}
func analyzeConfigured(ctx context.Context, dir, webhookURL string, rs []Rule, window time.Duration, paths int, limits replay.Options) (analysisReport, error) {
	report, err := analyzeInSession(ctx, dir, webhookURL, rs, window, paths, limits)
	if diskFull(err) {
		err = fmt.Errorf("会话目录所在磁盘空间不足：本地分析在会话目录内构建结果，所需空间与采集证据大小相当（%s）：%w", dir, err)
	}
	return report, err
}

// analysisPendingBytes bounds the stored records waiting for or under rule
// matching. One record larger than this is still analysed on its own.
const analysisPendingBytes = 64 << 20

// analysisJob is one stored record on its way through rule matching.
type analysisJob struct {
	id, at, client string
	raw            []byte
	size           int
	record         Transaction
	err            error
	done           chan struct{}
}

func analyzeInSession(ctx context.Context, dir, webhookURL string, rs []Rule, window time.Duration, paths int, limits replay.Options) (analysisReport, error) {
	report := analysisReport{EngineVersion: analysisEngineVersion, Rules: rs, ScanWindow: window, ScanPaths: paths, Reconstructed: rawSession(dir), RequestLimit: limits.RequestLimit, ResponseLimit: limits.ResponseLimit}
	if err := validateAnalysisDestination(dir); err != nil {
		return report, err
	}
	lock, err := os.Open(filepath.Join(dir, "capture.lock"))
	if err == nil {
		defer lock.Close()
		if err = session.LockFile(lock, false); err != nil {
			return report, errors.New("stop capture before local analysis")
		}
		defer session.UnlockFile(lock)
	} else if !os.IsNotExist(err) {
		return report, err
	} else {
		// Legacy/imported sessions may not carry a lock file.
		status, _ := readTUIStatus(dir)
		if status.State == "running" || status.State == "starting" || status.State == "stale" {
			return report, errors.New("stop capture before local analysis")
		}
	}
	var source *sql.DB
	if !report.Reconstructed {
		source, err = index.OpenDB(dir, false)
		if err != nil {
			return report, err
		}
		defer source.Close()
	}
	report.Source, err = sourceSignature(dir)
	if err != nil {
		return report, err
	}
	// Building next to the session keeps large analyses off a RAM-backed /tmp
	// and lets publication rename the file instead of copying it.
	build, err := createAnalysisBuild(dir)
	if err != nil {
		return report, err
	}
	defer removeAnalysisBuild(dir, build)
	db, err := openAnalysisBuild(filepath.Join(dir, build))
	if err != nil {
		return report, err
	}
	defer db.Close()
	if report.Reconstructed {
		stats, err := replay.Build(ctx, dir, db, limits)
		if err != nil {
			return report, err
		}
		report.Reconstruction = &stats
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM results"); err != nil {
		return report, err
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO results VALUES(?,?)")
	if err != nil {
		return report, err
	}
	defer stmt.Close()
	entries, err := tx.PrepareContext(ctx, "INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return report, err
	}
	defer entries.Close()
	scanner := &scanTracker{clients: map[string]*scanState{}}
	var rows *sql.Rows
	if report.Reconstructed {
		rows, err = tx.QueryContext(ctx, "SELECT id,time,client,data FROM requests ORDER BY time,id")
	} else {
		rows, err = source.QueryContext(ctx, "SELECT id,time,client,data FROM requests ORDER BY time,id")
	}
	if err != nil {
		return report, err
	}
	defer rows.Close()
	// Decoding and rule matching run on every CPU; scan correlation and writes
	// stay in source order on this goroutine, so results match a serial run.
	work := make(chan *analysisJob)
	var workers sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		workers.Add(1)
		go func(work <-chan *analysisJob) {
			defer workers.Done()
			for job := range work {
				if job.record, job.err = session.DecodeTransaction(job.raw); job.err == nil {
					job.record.Alerts = detectWithLimits(job.record, rs, limits.RequestLimit, limits.ResponseLimit)
				}
				job.raw = nil
				close(job.done)
			}
		}(work)
	}
	defer workers.Wait()
	var pending []*analysisJob
	pendingBytes := 0
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			close(work)
		}
	}
	defer stop()
	finish := func() error {
		job := pending[0]
		pending[0] = nil
		pending = pending[1:]
		<-job.done
		pendingBytes -= job.size
		if job.err != nil {
			return job.err
		}
		record := job.record
		if alert := scanWithState(record, scanner, window, paths); alert != nil {
			record.Alerts = append(record.Alerts, *alert)
		}
		if record.Alerts == nil {
			record.Alerts = []Alert{}
		}
		// Entries are keyed and timed like the source row so list order and
		// filters match the stored index exactly.
		values, err := entryValues(job.id, job.at, job.client, record)
		if err != nil {
			return err
		}
		if _, err = stmt.ExecContext(ctx, job.id, values[entryAlertsColumn]); err != nil {
			return err
		}
		if _, err = entries.ExecContext(ctx, values...); err != nil {
			return err
		}
		report.Transactions++
		report.Alerts += uint64(len(record.Alerts))
		if report.Transactions%1000 == 0 {
			fmt.Fprintf(os.Stderr, "本地分析：已处理 %d 条事务，%d 条告警\n", report.Transactions, report.Alerts)
		}
		return nil
	}
	maxPending := 4 * runtime.GOMAXPROCS(0)
	for rows.Next() {
		var at, client sql.NullString
		job := &analysisJob{done: make(chan struct{})}
		if err = rows.Scan(&job.id, &at, &client, &job.raw); err != nil {
			return report, err
		}
		job.at, job.client, job.size = at.String, client.String, len(job.raw)
		// Bound records in flight by count and by stored size: a few large
		// bodies must not multiply memory by the number of CPUs.
		for len(pending) > 0 && (len(pending) >= maxPending || pendingBytes+job.size > analysisPendingBytes) {
			if err = finish(); err != nil {
				return report, err
			}
		}
		select {
		case work <- job:
		case <-ctx.Done():
			return report, ctx.Err()
		}
		pending = append(pending, job)
		pendingBytes += job.size
	}
	if err = rows.Err(); err != nil {
		return report, err
	}
	for len(pending) > 0 {
		if err = finish(); err != nil {
			return report, err
		}
	}
	stop()
	if err = rows.Close(); err != nil {
		return report, err
	}
	if scanner.skipped != (scanSkipped{}) {
		skipped := scanner.skipped
		report.ScanSkipped = &skipped
	}
	if _, err = tx.ExecContext(ctx, entriesIndexes); err != nil {
		return report, err
	}
	if report.Reconstructed {
		if _, err = tx.ExecContext(ctx, "CREATE VIEW records AS "+recordsSelect("requests", "entries")); err != nil {
			return report, err
		}
	}
	signature, err := sourceSignature(dir)
	if err != nil {
		return report, err
	}
	if signature != report.Source {
		return report, errors.New("capture index changed during analysis; retry after capture stops")
	}
	ruleData, _ := json.Marshal(struct {
		Version       int
		Rules         []Rule
		Window        time.Duration
		Paths         int
		RequestLimit  int
		ResponseLimit int
	}{analysisEngineVersion, rs, window, paths, limits.RequestLimit, limits.ResponseLimit})
	hash := sha256.Sum256(ruleData)
	report.RulesSHA256 = hex.EncodeToString(hash[:])
	report.IntegrityWarnings = sessionIntegrityWarnings(dir, report.Reconstruction)
	report.Completed = time.Now().UTC()
	data, err := json.Marshal(report)
	if err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR REPLACE INTO metadata VALUES(1,?)", string(data)); err != nil {
		return report, err
	}
	if err = tx.Commit(); err != nil {
		return report, err
	}
	if err = db.Close(); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = publishAnalysis(ctx, dir, build); err != nil {
		return report, err
	}
	// Explicitly requested delivery happens only after successful publication.
	if webhookURL != "" {
		delivery := &deliveryReport{}
		webhook := newAlertWebhook(delivery, webhookURL, os.Getenv("TRAFFIC_WEBHOOK_TOKEN"))
		defer webhook.close()
		view, err := openStore(dir)
		if err != nil {
			return report, err
		}
		defer view.db.Close()
		rows, err := view.db.QueryContext(ctx, "SELECT data FROM records WHERE alert>0 ORDER BY time,id")
		if err != nil {
			return report, err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var record Transaction
			if err = rows.Scan(&raw); err != nil {
				return report, err
			}
			if err = json.Unmarshal(raw, &record); err != nil {
				return report, err
			}
			for _, alert := range record.Alerts {
				payload, _ := json.Marshal(map[string]any{"id": record.ID, "url": record.URL, "client": record.Client, "peer_client": record.PeerClient, "client_source": record.ClientSource, "time": record.Time, "alert": alert})
				webhook.enqueue(payload)
			}
		}
		if err = rows.Err(); err != nil {
			return report, err
		}
		webhook.close()
		report.Delivery = &delivery.stats
	}
	return report, nil
}

func readAnalysisReport(dir string) (*analysisReport, error) {
	if err := validateAnalysisDestination(dir); err != nil {
		return nil, err
	}
	db, err := openAnalysisDB(dir)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var raw []byte
	var report analysisReport
	if err = db.QueryRow("SELECT data FROM metadata WHERE id=1").Scan(&raw); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &report); err != nil {
		return nil, err
	}
	signature, err := sourceSignature(dir)
	if err != nil {
		return nil, err
	}
	if report.Source != signature {
		return nil, errors.New("采集索引已变化，请重新运行 traffic-console analyze")
	}
	return &report, nil
}
