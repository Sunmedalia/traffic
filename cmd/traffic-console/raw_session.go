package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/Sunmedalia/traffic/internal/replay"
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
		if report, layout, inspectErr := inspectAnalysis(dir, path); inspectErr == nil {
			var setup []index.Statement
			switch layout {
			case layoutResults:
				setup = legacyViews("main.results")
			case layoutBlob:
				// Engine 7 publishes no records view: assembling bodies needs
				// a connection function, so the view is per connection.
				setup = []index.Statement{{SQL: "CREATE TEMP VIEW records AS " + blobRecordsSelect("main.requests", "main.entries")}}
			}
			setup = append(setup, storedRecordsView(layout == layoutBlob))
			db, err := index.OpenReader(analysisURL(path, "ro"), storeReaders, setup...)
			if err != nil {
				return nil, err
			}
			return &Store{db: db, dir: dir, reader: true, analysis: report}, nil
		}
	}
	// Each :memory: connection is a separate database, so keep exactly one.
	db, err := sql.Open(index.Driver, ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(replay.RequestsTable + `;` + entriesTable + `;CREATE VIEW records AS ` + blobRecordsSelect("requests", "entries") + `;` + storedRecordsView(true).SQL); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, dir: dir, reader: true, analysisNote: "原始采集会话尚未还原或输入已变化；请运行 traffic-console analyze，或在 Web「分析」页中开始分析"}, nil
}
