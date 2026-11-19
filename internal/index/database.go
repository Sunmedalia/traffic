package index

import (
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Sunmedalia/traffic/internal/session"
)

// OpenDB opens the v1 session index. Readers always use SQLite mode=ro.
func OpenDB(dir string, write bool) (*sql.DB, error) {
	if write {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		if err := session.RestrictDirectory(dir); err != nil {
			return nil, err
		}
	}
	mode := "ro"
	if write {
		mode = "rwc"
	}
	dsn, err := IndexDSN(dir, mode)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(Driver, dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if write {
		_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, time TEXT, client TEXT, alert INTEGER, data BLOB); CREATE INDEX IF NOT EXISTS requests_time ON requests(time DESC); CREATE INDEX IF NOT EXISTS requests_alert_time ON requests(time DESC) WHERE alert>0;`)
		os.Chmod(filepath.Join(dir, "index.sqlite"), 0600)
	} else {
		err = db.Ping()
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// IndexDSN is the SQLite URL of the v1 session index in dir.
func IndexDSN(dir, mode string) (string, error) {
	absolute, err := filepath.Abs(filepath.Join(dir, "index.sqlite"))
	if err != nil {
		return "", err
	}
	databasePath := filepath.ToSlash(absolute)
	if runtime.GOOS == "windows" {
		databasePath = "/" + databasePath
	}
	databaseURL := url.URL{Scheme: "file", Path: databasePath}
	query := databaseURL.Query()
	query.Set("mode", mode)
	query.Set("_busy_timeout", "5000")
	databaseURL.RawQuery = query.Encode()
	return databaseURL.String(), nil
}
