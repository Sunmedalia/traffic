package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Sunmedalia/traffic/internal/index"
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
	reader       bool
	analysis     *analysisReport
	analysisNote string
}

func openStore(dir string) (*Store, error) {
	before, _ := analysisDatabasePath(dir)
	s, err := openStoreOnce(dir)
	if err != nil {
		after, pathErr := analysisDatabasePath(dir)
		if pathErr == nil && before != after {
			return openStoreOnce(dir)
		}
	}
	return s, err
}

func openStoreOnce(dir string) (*Store, error) {
	if rawSession(dir) {
		return openRawStore(dir)
	}
	dsn, err := index.IndexDSN(dir, "ro")
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, reader: true}
	var setup []index.Statement
	if analysisExists(dir) {
		if err := validateAnalysisDestination(dir); err != nil {
			return nil, err
		}
		path, err := analysisDatabasePath(dir)
		if err != nil {
			return nil, err
		}
		report, columns, err := inspectAnalysis(dir, path)
		if err != nil {
			s.analysisNote = "本地分析结果不可用：采集索引已变化或分析库无效，请重新运行 traffic-console analyze"
			setup = legacyViews("")
		} else {
			// Results contain alerts and list fields only; bodies always come from collected evidence.
			setup = []index.Statement{{SQL: "ATTACH DATABASE ? AS analysis", Args: []any{analysisURL(path, "ro")}}}
			if columns {
				setup = append(setup, index.Statement{SQL: "CREATE TEMP VIEW records AS " + recordsSelect("main.requests", "analysis.entries")})
			} else {
				setup = append(setup, legacyViews("analysis.results")...)
			}
			s.analysis = report
		}
	} else {
		setup = legacyViews("")
		var manifest struct {
			DetectionMode string `json:"detection_mode"`
		}
		if data, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err == nil && json.Unmarshal(data, &manifest) == nil && manifest.DetectionMode == "offline" {
			s.analysisNote = "尚未执行本地规则分析；运行 traffic-console analyze --session DIR 后查看告警"
		}
	}
	if s.db, err = index.OpenReader(dsn, storeReaders, setup...); err != nil {
		return nil, err
	}
	return s, nil
}
