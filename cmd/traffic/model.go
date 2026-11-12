package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

type Transaction = session.Transaction
type Alert = session.Alert
type Stats = session.Stats

const indexTimeFormat = session.IndexTimeFormat

var serial atomic.Uint64

type Store struct {
	localAddresses map[string]bool
	packetDrops    map[string]uint64
	fatal          error
	db             *sql.DB
	dir            string
	mu             sync.Mutex
	stats          Stats
}

func openStore(dir string, write bool) (*Store, error) {
	db, err := session.OpenDB(dir, write)
	if err != nil {
		return nil, err
	}
	addresses := map[string]bool{}
	interfaces, _ := net.InterfaceAddrs()
	for _, address := range interfaces {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil {
			addresses[ip.String()] = true
		}
	}
	return &Store{db: db, dir: dir, localAddresses: addresses, stats: Stats{Started: time.Now().UTC(), State: "running", TLS: "disabled"}}, nil
}
func (s *Store) save(t Transaction) error {
	if t.PID > 0 {
		if target, err := processTarget("/proc", t.PID); err == nil {
			t.Service = target.Service
			t.TargetID = target.ID
			s.mu.Lock()
			for _, selected := range s.stats.Targets {
				if selected.ID == target.ID {
					_, portText, _ := net.SplitHostPort(t.LocalEndpoint)
					port, _ := strconv.Atoi(portText)
					serverLocal := false
					for _, listeningPort := range selected.Ports {
						if port == listeningPort {
							serverLocal = true
							break
						}
					}
					if !serverLocal {
						t.LocalEndpoint = t.Client
					}
					t.Service = selected.Service
					break
				}
			}
			s.mu.Unlock()
		}
	}
	if t.PID > 0 {
		t.Backend = "openssl"
		if strings.Contains(t.Connection, "tls:java:") {
			t.Backend = "java-agent"
		}
	} else {
		t.Backend = "pcap"
		host, portText, _ := net.SplitHostPort(t.LocalEndpoint)
		port, _ := strconv.Atoi(portText)
		ip := net.ParseIP(host)
		local := ip != nil && (ip.IsLoopback() || s.localAddresses[ip.String()])
		s.mu.Lock()
		for _, target := range s.stats.Targets {
			for _, localPort := range target.Ports {
				if local && localPort == port {
					if t.Service != "" && t.Service != target.Service {
						t.Service = "unknown"
					} else if t.Service == "" {
						t.Service = target.Service
					}
				}
			}
		}
		s.mu.Unlock()
	}
	if strings.HasPrefix(t.Connection, "tls:iis:") {
		t.Backend = "iis-httpapi"
	}
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
