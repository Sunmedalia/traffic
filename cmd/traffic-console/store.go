package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Sunmedalia/traffic/internal/session"
)

type Transaction = session.Transaction
type Alert = session.Alert
type Stats = session.Stats

const indexTimeFormat = session.IndexTimeFormat

// The analyst opens existing sessions read-only and keeps no capture state.
type Store struct {
	db           *sql.DB
	dir          string
	analysis     *analysisReport
	analysisNote string
}

func openStore(dir string) (*Store, error) {
	db, err := session.OpenDB(dir, false)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, dir: dir}
	if _, err := os.Stat(filepath.Join(dir, "analysis.sqlite")); err == nil {
		report, err := readAnalysisReport(dir)
		if err != nil {
			s.analysisNote = "本地分析结果不可用：" + err.Error()
			return s, nil
		}
		if _, err = db.Exec("ATTACH DATABASE ? AS analysis", analysisURL(filepath.Join(dir, "analysis.sqlite"), "ro")); err != nil {
			db.Close()
			return nil, err
		}
		// The temporary view shadows main.requests only on this read connection.
		// Results contain alerts only; bodies always come from collected evidence.
		_, err = db.Exec(`CREATE TEMP VIEW requests AS
SELECT r.id,r.time,r.client,
 CASE WHEN a.id IS NULL THEN r.alert ELSE json_array_length(a.alerts) END AS alert,
 CASE WHEN a.id IS NULL THEN r.data ELSE json_set(CAST(r.data AS TEXT),'$.alerts',json(a.alerts)) END AS data
FROM main.requests r LEFT JOIN analysis.results a ON a.id=r.id`)
		if err != nil {
			db.Close()
			return nil, err
		}
		s.analysis = report
	} else if !os.IsNotExist(err) {
		db.Close()
		return nil, err
	} else {
		// Without the analysis temp view, independent read connections are safe.
		// Analysis stores keep one connection because the view is connection-local.
		s.db.SetMaxOpenConns(4)
		s.db.SetMaxIdleConns(4)
		var manifest struct {
			DetectionMode string `json:"detection_mode"`
		}
		if data, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err == nil && json.Unmarshal(data, &manifest) == nil && manifest.DetectionMode == "offline" {
			s.analysisNote = "尚未执行本地规则分析；运行 traffic-console analyze --session DIR 后查看告警"
		}
	}
	return s, nil
}
