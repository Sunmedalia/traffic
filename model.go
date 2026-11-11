package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Transaction struct {
	Host          string    `json:"host,omitempty"`
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	Time          time.Time `json:"time"`
	Source        string    `json:"source"`
	Client        string    `json:"client"`
	Connection    string    `json:"connection"`
	Method        string    `json:"method"`
	URL           string    `json:"url"`
	Request       []byte    `json:"request,omitempty"`
	Response      []byte    `json:"response,omitempty"`
	Status        int       `json:"status"`
	Incomplete    bool      `json:"incomplete"`
	Truncated     bool      `json:"truncated"`
	PID           int       `json:"pid,omitempty"`
	Alerts        []Alert   `json:"alerts,omitempty"`
}
type Alert struct {
	View     string `json:"view,omitempty"`
	Version  int    `json:"version"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Field    string `json:"field"`
	Match    string `json:"match"`
	Decoding int    `json:"decoding"`
}
type Stats struct {
	ResourceLimits string    `json:"resource_limits"`
	TLSDropped     uint64    `json:"tls_dropped"`
	QueueDropped   uint64    `json:"queue_dropped"`
	Started        time.Time `json:"started"`
	State          string    `json:"state"`
	Packets        uint64    `json:"packets"`
	Transactions   uint64    `json:"transactions"`
	Alerts         uint64    `json:"alerts"`
	Dropped        uint64    `json:"dropped"`
	TLS            string    `json:"tls"`
	Errors         []string  `json:"errors,omitempty"`
}

const indexTimeFormat = "2006-01-02T15:04:05.000000000Z"

var serial atomic.Uint64

type Store struct {
	packetDrops map[string]uint64
	fatal       error
	db          *sql.DB
	dir         string
	mu          sync.Mutex
	stats       Stats
}

func openStore(dir string, write bool) (*Store, error) {
	if write {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		os.Chmod(dir, 0700)
	}
	mode := "ro"
	if write {
		mode = "rwc"
	}
	absolute, err := filepath.Abs(filepath.Join(dir, "index.sqlite"))
	if err != nil {
		return nil, err
	}
	databaseURL := url.URL{Scheme: "file", Path: absolute}
	query := databaseURL.Query()
	query.Set("mode", mode)
	query.Set("_busy_timeout", "5000")
	databaseURL.RawQuery = query.Encode()
	db, err := sql.Open("sqlite3", databaseURL.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, dir: dir, stats: Stats{Started: time.Now().UTC(), State: "running", TLS: "disabled"}}
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
	return s, nil
}
func (s *Store) save(t Transaction) error {
	t.SchemaVersion = 1
	if t.ID == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d/%s", t.Connection, t.Source, time.Now().UnixNano(), t.URL)))
		t.ID = hex.EncodeToString(h[:12])
	}
	t.Alerts = detect(t)
	if a := scan(t); a != nil {
		t.Alerts = append(t.Alerts, *a)
	}
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	var previous int
	e := s.db.QueryRow("SELECT alert FROM requests WHERE id=?", t.ID).Scan(&previous)
	fresh := e == sql.ErrNoRows
	if e != nil && !fresh {
		return e
	}
	_, err = s.db.Exec("INSERT OR REPLACE INTO requests VALUES(?,?,?,?,?)", t.ID, t.Time.UTC().Format(indexTimeFormat), t.Client, len(t.Alerts), b)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if fresh {
		s.stats.Transactions++
	}
	if len(t.Alerts) > previous {
		s.stats.Alerts += uint64(len(t.Alerts) - previous)
	}
	s.mu.Unlock()
	for i, a := range t.Alerts {
		if i < previous {
			continue
		}
		out, _ := json.Marshal(map[string]any{"id": t.ID, "url": t.URL, "client": t.Client, "alert": a})
		fmt.Println(string(out))
	}
	return nil
}
func (s *Store) report() {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.MarshalIndent(s.stats, "", "  ")
	tmp := filepath.Join(s.dir, "status.tmp")
	if os.WriteFile(tmp, b, 0600) == nil {
		os.Rename(tmp, filepath.Join(s.dir, "status.json"))
	}
}
func (s *Store) problem(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.stats.Errors) < 100 {
		s.stats.Errors = append(s.stats.Errors, err.Error())
	}
}

func (s *Store) fail(err error) {
	s.problem(err)
	s.mu.Lock()
	if s.fatal == nil {
		s.fatal = err
	}
	s.mu.Unlock()
}

func (s *Store) recordPacketDrops(iface string, drops uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.packetDrops == nil {
		s.packetDrops = make(map[string]uint64)
	}
	s.packetDrops[iface] = drops
	s.stats.Dropped = 0
	for _, count := range s.packetDrops {
		s.stats.Dropped += count
	}
}

// Restore a persisted request when its response arrives, keeping pending queues small.
func (s *Store) restore(record *Transaction) error {
	var data []byte
	if err := s.db.QueryRow("SELECT data FROM requests WHERE id=?", record.ID).Scan(&data); err != nil {
		return err
	}
	return json.Unmarshal(data, record)
}
