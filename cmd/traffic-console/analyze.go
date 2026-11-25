package main

import (
	"bufio"
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
// Engine 6 keeps reconstructing new connections while unanswered SYNs or
// idle keep-alive connections would have filled every parser.
// Engine 7 stores reconstructed bodies as raw BLOBs beside metadata JSON and
// lets a re-analysis reuse an earlier generation's reconstruction.
const analysisEngineVersion = 7

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
	// ReconstructionVersion is the replay.Version that produced the requests.
	ReconstructionVersion int `json:"reconstruction_version,omitempty"`
	// ReconstructionReused reports that this run copied the requests of the
	// previous generation instead of replaying the evidence again.
	ReconstructionReused bool `json:"reconstruction_reused,omitempty"`
	// ReconstructedAt is when the evidence was last actually replayed.
	ReconstructedAt time.Time `json:"reconstructed_at,omitzero"`
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
	if _, err = db.Exec(`PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF; PRAGMA cache_size=-65536; PRAGMA temp_store=MEMORY; PRAGMA locking_mode=EXCLUSIVE;
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
	id, at, client    string
	raw               []byte
	request, response []byte
	size              int
	record            Transaction
	err               error
	done              chan struct{}
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
		report.ReconstructionVersion = replay.Version
		reused, err := reuseReconstruction(ctx, dir, db, &report)
		if err != nil {
			return report, err
		}
		if !reused {
			stats, err := replay.Build(ctx, dir, db, limits)
			if err != nil {
				return report, err
			}
			report.Reconstruction = &stats
			report.ReconstructedAt = time.Now().UTC()
		}
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
		rows, err = tx.QueryContext(ctx, "SELECT id,time,client,data,request_raw,response_raw FROM requests ORDER BY time,id")
	} else {
		rows, err = source.QueryContext(ctx, "SELECT id,time,client,data,NULL,NULL FROM requests ORDER BY time,id")
	}
	if err != nil {
		return report, err
	}
	defer rows.Close()
	// Decoding and rule matching run on every CPU; scan correlation and writes
	// stay in source order on this goroutine, so results match a serial run.
	fieldPlan := planRuleFields(rs)
	work := make(chan *analysisJob)
	var workers sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		workers.Add(1)
		go func(work <-chan *analysisJob) {
			defer workers.Done()
			br := bufio.NewReaderSize(nil, 4096)
			for job := range work {
				// Engine 7 metadata carries no bodies, so decoding no longer
				// base64-decodes them; v1 index records still embed theirs.
				if job.record, job.err = session.DecodeTransaction(job.raw); job.err == nil {
					if len(job.request) > 0 {
						job.record.Request = job.request
					}
					if len(job.response) > 0 {
						job.record.Response = job.response
					}
					job.record.Alerts = detectWithPlan(job.record, rs, fieldPlan, limits.RequestLimit, limits.ResponseLimit, br)
				}
				job.raw, job.request, job.response = nil, nil, nil
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
		if err = rows.Scan(&job.id, &at, &client, &job.raw, &job.request, &job.response); err != nil {
			return report, err
		}
		job.at, job.client, job.size = at.String, client.String, len(job.raw)+len(job.request)+len(job.response)
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
		rows, err := view.db.QueryContext(ctx, `SELECT e.id,e.time,e.client,e.url,e.alerts,
 COALESCE(json_extract(CAST(r.data AS TEXT),'$.peer_client'),''),
 COALESCE(json_extract(CAST(r.data AS TEXT),'$.client_source'),'')
 FROM entries e JOIN requests r ON r.id=e.id WHERE e.alert>0 ORDER BY e.time,e.id`)
		if err != nil {
			return report, err
		}
		defer rows.Close()
		for rows.Next() {
			var id, at, client, reqURL, peerClient, clientSource string
			var rawAlerts []byte
			if err = rows.Scan(&id, &at, &client, &reqURL, &rawAlerts, &peerClient, &clientSource); err != nil {
				return report, err
			}
			var alerts []Alert
			if err = json.Unmarshal(rawAlerts, &alerts); err != nil {
				return report, err
			}
			var stamp any = at
			if parsed, parseErr := time.Parse(indexTimeFormat, at); parseErr == nil {
				stamp = parsed
			}
			for _, alert := range alerts {
				payload, _ := json.Marshal(map[string]any{
					"id":            id,
					"url":           reqURL,
					"client":        client,
					"peer_client":   peerClient,
					"client_source": clientSource,
					"time":          stamp,
					"alert":         alert,
				})
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

// requestsColumns is the engine 7 requests layout, in table order.
const requestsColumns = "id,time,client,alert,data,request_raw,response_raw"

// reuseReconstruction fills db with the requests and reconstruction of the
// current generation when that generation replayed the same evidence (source
// signature) with the same replay version and body limits, so a run that only
// changes rules or scan settings skips replay.Build. It returns false, with db
// left empty, when no generation qualifies or the copy fails; the caller then
// replays the evidence. The earlier generation is only ever attached read-only.
func reuseReconstruction(ctx context.Context, dir string, db *sql.DB, report *analysisReport) (bool, error) {
	if !analysisExists(dir) {
		return false, nil
	}
	path, err := analysisDatabasePath(dir)
	if err != nil {
		return false, nil
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	// A generation removed by a concurrent publication fails to attach and
	// simply means a full replay.
	if _, err = conn.ExecContext(ctx, "ATTACH DATABASE ? AS previous", analysisURL(path, "ro")); err != nil {
		return false, nil
	}
	defer conn.ExecContext(context.Background(), "DETACH DATABASE previous")
	// Decide from the attached file itself, not from an earlier inspection,
	// so the pointer moving in between cannot pair stale requests with a match.
	previous, layout, err := readAnalysisSchema(ctx, conn, "previous")
	if err != nil || layout != layoutBlob || !previous.Reconstructed ||
		previous.ReconstructionVersion != replay.Version ||
		previous.RequestLimit != report.RequestLimit || previous.ResponseLimit != report.ResponseLimit ||
		previous.Source == "" || previous.Source != report.Source {
		return false, nil
	}
	var columns string
	if err = conn.QueryRowContext(ctx, "SELECT group_concat(name,',') FROM (SELECT name FROM pragma_table_info('requests','previous') ORDER BY cid)").Scan(&columns); err != nil || columns != requestsColumns {
		return false, nil
	}
	var stats, gaps []byte
	if err = conn.QueryRowContext(ctx, "SELECT stats,gaps FROM previous.reconstruction WHERE id=1").Scan(&stats, &gaps); err != nil {
		return false, nil
	}
	var reconstruction Stats
	if err = json.Unmarshal(stats, &reconstruction); err != nil {
		return false, nil
	}
	// INSERT ... SELECT * into an empty table of the same layout lets SQLite
	// copy records page by page without decoding them.
	copyErr := func() error {
		for _, statement := range []string{
			replay.RequestsTable,
			"INSERT INTO main.requests SELECT * FROM previous.requests",
			replay.RequestsIndex,
			replay.ReconstructionTable,
		} {
			if _, err := conn.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		_, err := conn.ExecContext(ctx, "INSERT INTO main.reconstruction VALUES(1,?,?)", stats, gaps)
		return err
	}()
	if copyErr != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if _, err = conn.ExecContext(ctx, "DROP TABLE IF EXISTS main.requests; DROP TABLE IF EXISTS main.reconstruction"); err != nil {
			return false, err
		}
		fmt.Fprintf(os.Stderr, "本地分析：复用上次还原结果失败，改为重新还原：%v\n", copyErr)
		return false, nil
	}
	report.Reconstruction = &reconstruction
	report.ReconstructionReused = true
	report.ReconstructedAt = previous.ReconstructedAt
	if report.ReconstructedAt.IsZero() {
		report.ReconstructedAt = previous.Completed
	}
	fmt.Fprintln(os.Stderr, "本地分析：证据与还原参数未变，复用上次还原结果，跳过 PCAP/TLS 重放")
	return true, nil
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
