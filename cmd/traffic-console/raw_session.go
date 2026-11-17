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
		db, err := openAnalysisDB(dir, false)
		if err != nil {
			return nil, err
		}
		s := &Store{db: db, dir: dir}
		if err = s.useAnalysis("main"); err == nil {
			return s, nil
		}
		db.Close()
	}
	db, err := sql.Open(index.Driver, ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE requests(id TEXT PRIMARY KEY,time TEXT,client TEXT,alert INTEGER,data BLOB)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, dir: dir, analysisNote: "原始采集会话尚未还原或输入已变化；请运行 traffic-console analyze，或在 Web「分析」页中开始分析"}, nil
}

func (s *Store) useAnalysis(schema string) error {
	var data []byte
	var report analysisReport
	if err := s.db.QueryRow("SELECT data FROM " + schema + ".metadata WHERE id=1").Scan(&data); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return err
	}
	signature, err := sourceSignature(s.dir)
	if err != nil {
		return err
	}
	if signature != report.Source {
		return os.ErrInvalid
	}
	_, err = s.db.Exec(`CREATE TEMP VIEW requests AS
SELECT r.id,r.time,r.client,
 CASE WHEN a.id IS NULL THEN r.alert ELSE json_array_length(a.alerts) END AS alert,
 CASE WHEN a.id IS NULL THEN r.data ELSE json_set(CAST(r.data AS TEXT),'$.alerts',json(a.alerts)) END AS data
FROM main.requests r LEFT JOIN ` + schema + `.results a ON a.id=r.id`)
	if err == nil {
		s.analysis = &report
	}
	return err
}
