package replay

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/Sunmedalia/traffic/internal/session"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Transaction = session.Transaction
type Alert = session.Alert
type Stats = session.Stats

const indexTimeFormat = session.IndexTimeFormat

var serial atomic.Uint64
var requestLimit = 256 << 10
var responseLimit = 64 << 10
var capturePorts = map[int]bool{80: true, 443: true}

type Store struct {
	requests                           requestCache
	indexMu                            sync.Mutex
	indexTx                            *sql.Tx
	indexRead, indexWrite, indexExists *sql.Stmt
	indexBatching                      bool
	indexOps, indexBytes               int
	db                                 *sql.DB
	dir                                string
	mu                                 sync.Mutex
	stats                              Stats
	fatal                              error
	localAddresses                     map[string]bool
	gaps                               []session.GapEvent
}

func openStore(dir string, write bool) (*Store, error) {
	db, err := index.OpenDB(dir, write)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, dir: dir, localAddresses: map[string]bool{}}, nil
}
func (s *Store) save(t Transaction) error {
	if t.PID > 0 {
		// Once a request has a start identity, keep it when its response is
		// restored. Looking up the PID again could reassign old evidence to a
		// different process after PID reuse.
		identity := t.TargetID
		s.mu.Lock()
		for _, selected := range s.stats.Targets {
			if identity == "" || selected.ID != identity || selected.PID != t.PID {
				continue
			}
			t.TargetID = identity
			t.Service = selected.Service
			_, portText, _ := net.SplitHostPort(t.LocalEndpoint)
			port, _ := strconv.Atoi(portText)
			serverLocal := slices.Contains(selected.Ports, port)
			if !serverLocal {
				t.LocalEndpoint = t.Client
				if t.PeerClient != "" {
					t.LocalEndpoint = t.PeerClient
				}
			}
			break
		}
		s.mu.Unlock()

	}
	if t.Backend == "" {
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
	t.Alerts = nil
	if _, err := s.persist(t); err != nil {
		return err
	}
	s.requests.put(t)
	return nil
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
	*record = Transaction{}
	return json.Unmarshal(data, record)
}
