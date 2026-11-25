package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"

	"github.com/Sunmedalia/traffic/internal/index"
)

// Every store exposes two relations to the query layer:
//
//   - entries: one narrow row per transaction carrying the fields lists,
//     filters and summaries need, plus the alert array. It never holds bodies.
//   - records: id, time, client, alert and the full transaction JSON with its
//     alerts merged in. Only single-record reads (detail, export) use it.
//
// Analyses from engine 5 store entries as a table, so filtering no longer
// parses every body-sized JSON record. Older layouts (v1 indexes and earlier
// analysis generations) get connection-local views computing the same columns.
const entriesTable = `CREATE TABLE entries(
 id TEXT PRIMARY KEY,
 time TEXT NOT NULL,
 client TEXT NOT NULL,
 alert INTEGER NOT NULL,
 severity INTEGER NOT NULL,
 rule TEXT NOT NULL,
 alerts TEXT NOT NULL,
 method TEXT NOT NULL,
 host TEXT NOT NULL,
 url TEXT NOT NULL,
 status INTEGER NOT NULL,
 service TEXT NOT NULL,
 incomplete INTEGER NOT NULL,
 truncated INTEGER NOT NULL)`

// Indexes are built after the bulk insert, which is cheaper than maintaining them per row.
const entriesIndexes = `CREATE INDEX entries_time ON entries(time,id);
CREATE INDEX entries_alert_time ON entries(time,id) WHERE alert>0;`

// recordsSelect merges alerts from an entries or legacy results relation into
// the stored transaction JSON. Both relations carry an alerts array column.
func recordsSelect(requests, alerts string) string {
	return `SELECT r.id,r.time,r.client,
 CASE WHEN a.id IS NULL THEN r.alert WHEN a.alerts='[]' THEN 0 ELSE json_array_length(a.alerts) END AS alert,
 CASE WHEN a.id IS NULL OR (r.alert=0 AND a.alerts='[]') THEN r.data ELSE json_set(CAST(r.data AS TEXT),'$.alerts',json(a.alerts)) END AS data
FROM ` + requests + ` r LEFT JOIN ` + alerts + ` a ON a.id=r.id`
}

// legacyEntriesView computes entries from JSON records. results names a legacy
// analysis results table, or is empty when alerts live inside the records.
func legacyEntriesView(results string) string {
	embedded := `COALESCE(json_extract(CAST(r.data AS TEXT),'$.alerts'),'[]')`
	alert, alerts, join := "r.alert", embedded, ""
	if results != "" {
		join = " LEFT JOIN " + results + " a ON a.id=r.id"
		alert = "CASE WHEN a.id IS NULL THEN r.alert ELSE json_array_length(a.alerts) END"
		alerts = "CASE WHEN a.id IS NULL THEN " + embedded + " ELSE a.alerts END"
	}
	return `CREATE TEMP VIEW entries AS
SELECT b.id,b.time,b.client,b.alert,b.alerts,
 COALESCE((SELECT max(` + sqlSeverityRank + `) FROM json_each(b.alerts) a),0) AS severity,
 COALESCE((SELECT json_extract(a.value,'$.rule') FROM json_each(b.alerts) a ORDER BY ` + sqlSeverityRank + ` DESC,a.key LIMIT 1),'') AS rule,
 COALESCE(json_extract(b.d,'$.method'),'') AS method,
 COALESCE(json_extract(b.d,'$.host'),'') AS host,
 COALESCE(json_extract(b.d,'$.url'),'') AS url,
 COALESCE(json_extract(b.d,'$.status'),0) AS status,
 COALESCE(json_extract(b.d,'$.service'),'') AS service,
 COALESCE(json_extract(b.d,'$.incomplete'),0) AS incomplete,
 COALESCE(json_extract(b.d,'$.truncated'),0) AS truncated
FROM (SELECT r.id,COALESCE(r.time,'') AS time,COALESCE(r.client,'') AS client,CAST(r.data AS TEXT) AS d,` + alert + ` AS alert,` + alerts + ` AS alerts
 FROM main.requests r` + join + `) b`
}

// legacyViews prepares a connection over a layout without an entries table.
func legacyViews(results string) []index.Statement {
	records := `CREATE TEMP VIEW records AS SELECT id,time,client,alert,data FROM main.requests`
	if results != "" {
		records = `CREATE TEMP VIEW records AS ` + recordsSelect("main.requests", results)
	}
	return []index.Statement{{SQL: legacyEntriesView(results)}, {SQL: records}}
}

// entryAlertsColumn is the position of the alerts JSON in an entryValues row.
const entryAlertsColumn = 6

// entryValues returns the entries row of record, whose alerts are final.
func entryValues(id, at, client string, record Transaction) ([]any, error) {
	alerts, err := json.Marshal(record.Alerts)
	if err != nil {
		return nil, err
	}
	severity, rule := -1, ""
	for _, alert := range record.Alerts {
		if rank := severityRank(alert.Severity); rank > severity {
			severity, rule = rank, alert.Rule
		}
	}
	return []any{id, at, client, len(record.Alerts), max(severity, 0), rule, string(alerts),
		record.Method, record.Host, record.URL, record.Status, record.Service, record.Incomplete, record.Truncated}, nil
}

// inspectAnalysis reads a published generation's metadata and reports whether
// it stores the entries table. A stale or unreadable generation is an error.
func inspectAnalysis(dir, path string) (*analysisReport, bool, error) {
	db, err := sql.Open(index.Driver, analysisURL(path, "ro"))
	if err != nil {
		return nil, false, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var raw []byte
	var report analysisReport
	if err = db.QueryRow("SELECT data FROM metadata WHERE id=1").Scan(&raw); err != nil {
		return nil, false, err
	}
	if err = json.Unmarshal(raw, &report); err != nil {
		return nil, false, err
	}
	signature, err := sourceSignature(dir)
	if err != nil {
		return nil, false, err
	}
	if signature != report.Source {
		return nil, false, os.ErrInvalid
	}
	var tables int
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='entries'").Scan(&tables); err != nil {
		return nil, false, err
	}
	return &report, tables > 0, nil
}

// storeReaders is the read connection count of file-backed stores. Every
// connection carries its own temporary views, so concurrent web requests no
// longer queue behind a single connection.
const storeReaders = 4

// checkStoreSchema verifies the relations the query layer depends on.
func checkStoreSchema(ctx context.Context, db *sql.DB) error {
	for _, query := range []string{
		"SELECT id,time,client,alert,data FROM records LIMIT 0",
		"SELECT id,time,client,alert,severity,rule,alerts,method,host,url,status,service,incomplete,truncated FROM entries LIMIT 0",
	} {
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		rows.Close()
	}
	return nil
}
