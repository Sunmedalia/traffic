package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Sunmedalia/traffic/internal/index"
)

func rawSession(dir string) bool {
	var manifest struct {
		Mode string `json:"capture_mode"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	return err == nil && json.Unmarshal(data, &manifest) == nil && manifest.Mode == "raw"
}

func openRawStore(dir string) (*Store, error) {
	if err := validateAnalysisDestination(dir); err != nil {
		return nil, err
	}
	if analysisExists(dir) {
		path, err := analysisDatabasePath(dir)
		if err != nil {
			return nil, err
		}
		if report, columns, inspectErr := inspectAnalysis(dir, path); inspectErr == nil {
			var setup []index.Statement
			if !columns {
				setup = legacyViews("main.results")
			}
			db, err := index.OpenReader(analysisURL(path, "ro"), storeReaders, setup...)
			if err != nil {
				return nil, err
			}
			return &Store{db: db, dir: dir, analysis: report}, nil
		}
	}
	// Each :memory: connection is a separate database, so keep exactly one.
	db, err := sql.Open(index.Driver, ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE requests(id TEXT PRIMARY KEY,time TEXT,client TEXT,alert INTEGER,data BLOB);` + entriesTable + `;CREATE VIEW records AS ` + recordsSelect("requests", "entries")); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, dir: dir, analysisNote: "原始采集会话尚未还原或输入已变化；请运行 traffic-console analyze，或在 Web「分析」页中开始分析"}, nil
}
