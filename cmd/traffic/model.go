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
	"runtime"
	"slices"
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
	indexMu               sync.Mutex
	indexTx               *sql.Tx
	indexRead, indexWrite *sql.Stmt
	indexBatching         bool
	indexOps, indexBytes  int
	checkMu               sync.Mutex
	checks                map[string]captureCheck
	probeCheck            func(session.Target) captureCheck
	gapMu                 sync.Mutex
	gapEvents             uint64
	targetTimes           map[string]session.Target
	webhook               *alertWebhook
	localAddresses        map[string]bool
	packetDrops           map[string]uint64
	fatal                 error
	db                    *sql.DB
	dir                   string
	mu                    sync.Mutex
	stats                 Stats
}

func openStore(dir string, write bool) (*Store, error) {
	db, err := session.OpenDB(dir, write)
	if err != nil {
		return nil, err
	}
	addresses := map[string]bool{}
	var interfaces []net.Addr
	_ = inCaptureNamespace(func() error { var err error; interfaces, err = net.InterfaceAddrs(); return err })
	for _, address := range interfaces {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil {
			addresses[ip.String()] = true
		}
	}
	return &Store{db: db, dir: dir, localAddresses: addresses, stats: Stats{DiagnosticsVersion: 1, Started: time.Now().UTC(), State: "running", TLS: "disabled"}}, nil
}
func (s *Store) save(t Transaction) error {
	if t.PID > 0 {
		// Once a request has a start identity, keep it when its response is
		// restored. Looking up the PID again could reassign old evidence to a
		// different process after PID reuse.
		identity := t.TargetID
		if identity == "" {
			identity, _ = processIdentity("/proc", t.PID)
		}
		matched := false
		s.mu.Lock()
		for _, selected := range s.stats.Targets {
			if identity == "" || selected.ID != identity || selected.PID != t.PID {
				continue
			}
			matched = true
			t.TargetID = identity
			t.Service = selected.Service
			_, portText, _ := net.SplitHostPort(t.LocalEndpoint)
			port, _ := strconv.Atoi(portText)
			serverLocal := slices.Contains(selected.Ports, port)
			if !serverLocal && runtime.GOOS != "windows" {
				t.LocalEndpoint = t.Client
				if t.PeerClient != "" {
					t.LocalEndpoint = t.PeerClient
				}
			}
			break
		}
		s.mu.Unlock()
		if !matched && t.TargetID == "" {
			if target, err := processTarget("/proc", t.PID); err == nil {
				t.Service = target.Service
				t.TargetID = target.ID
			}
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
	if strings.HasPrefix(t.Connection, "tls:preload/") {
		t.Backend = "openssl-preload"
	}
	resolveClient(&t)
	t.SchemaVersion = 1
	if t.Protocol == "" && t.Method != "" {
		t.Protocol = "HTTP/1.1"
	}
	if t.Truncated && !slices.Contains(t.IntegrityReasons, "body_truncated") {
		t.IntegrityReasons = append(t.IntegrityReasons, "body_truncated")
	}
	if t.Incomplete && len(t.IntegrityReasons) == 0 {
		t.IntegrityReasons = []string{"stream_incomplete"}
	}
	if t.ID == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d/%s", t.Connection, t.Source, time.Now().UnixNano(), t.URL)))
		t.ID = hex.EncodeToString(h[:12])
	}
	t.Alerts = detect(t)
	if a := scan(t); a != nil {
		t.Alerts = append(t.Alerts, *a)
	}
	newAlerts, err := s.persist(t)
	if err != nil {
		return err
	}
	for _, a := range newAlerts {
		out, _ := json.Marshal(map[string]any{"id": t.ID, "url": t.URL, "client": t.Client, "peer_client": t.PeerClient, "client_source": t.ClientSource, "time": t.Time, "alert": a})
		fmt.Println(string(out))
		if s.webhook != nil {
			s.webhook.enqueue(out)
		}
	}
	return nil
}
func (s *Store) report() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.targetTimes == nil {
		s.targetTimes = map[string]session.Target{}
	}
	live := map[string]session.Target{}
	now := time.Now().UTC()
	for i := range s.stats.Targets {
		target := &s.stats.Targets[i]
		key := target.ID + "|" + target.Library
		previous := s.targetTimes[key]
		target.DiscoveredAt, target.StartingAt, target.ReadyAt = previous.DiscoveredAt, previous.StartingAt, previous.ReadyAt
		if target.DiscoveredAt.IsZero() {
			target.DiscoveredAt = now
		}
		if target.State == "starting" && target.StartingAt.IsZero() {
			target.StartingAt = now
		}
		if target.State == "attached" && target.ReadyAt.IsZero() {
			target.ReadyAt = now
		}
		live[key] = *target
	}
	s.targetTimes = live
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
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	var reader indexExecutor = s.db
	if s.indexTx != nil {
		reader = s.indexTx
	}
	var data []byte
	if err := s.indexReadRowLocked(reader, record.ID).Scan(&data); err != nil {
		return err
	}
	return json.Unmarshal(data, record)
}
