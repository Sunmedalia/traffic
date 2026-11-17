package replay

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Sunmedalia/traffic/internal/session"
)

type Options struct {
	RequestLimit  int
	ResponseLimit int
}

// Decoder configuration remains process-local while legacy parsers are migrated;
// serialize builds, with cancellation while waiting, rather than racing globals.
var buildSlot = make(chan struct{}, 1)

func Build(ctx context.Context, dir string, db *sql.DB, options Options) (session.Stats, error) {
	select {
	case buildSlot <- struct{}{}:
		defer func() { <-buildSlot }()
	case <-ctx.Done():
		return session.Stats{}, ctx.Err()
	}
	if options.RequestLimit < 1 || options.ResponseLimit < 1 {
		return session.Stats{}, errors.New("invalid reconstruction body limits")
	}
	oldRequest, oldResponse, oldPorts, oldProxies := requestLimit, responseLimit, capturePorts, trustedProxies
	defer func() {
		requestLimit, responseLimit, capturePorts, trustedProxies = oldRequest, oldResponse, oldPorts, oldProxies
	}()
	requestLimit, responseLimit = options.RequestLimit, options.ResponseLimit
	var manifest struct {
		Ports     []int            `json:"capture_ports"`
		Addresses []string         `json:"local_addresses"`
		Targets   []session.Target `json:"targets"`
		Proxies   []string         `json:"trusted_proxies"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return session.Stats{}, err
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		return session.Stats{}, err
	}
	capturePorts = map[int]bool{}
	for _, port := range manifest.Ports {
		capturePorts[port] = true
	}
	trustedProxies, err = parseTrustedProxies(strings.Join(manifest.Proxies, ","))
	if err != nil {
		return session.Stats{}, err
	}
	if _, err = db.Exec(`CREATE TABLE requests(id TEXT PRIMARY KEY,time TEXT,client TEXT,alert INTEGER,data BLOB);CREATE INDEX requests_time ON requests(time DESC);CREATE INDEX requests_alert_time ON requests(time DESC) WHERE alert>0;`); err != nil {
		return session.Stats{}, err
	}
	s := &Store{db: db, dir: dir, localAddresses: map[string]bool{}, stats: Stats{Targets: manifest.Targets}}
	for _, address := range manifest.Addresses {
		s.localAddresses[address] = true
	}
	p := newHTTP(s)
	// Bounded batches write only the disposable local build, never raw evidence.
	stopIndex := s.startIndexWriter(ctx)
	defer stopIndex()
	files, err := session.PacketFiles(dir)
	if err != nil {
		return s.stats, err
	}
	groups := map[string][]string{}
	for _, file := range files {
		base := strings.TrimSuffix(filepath.Base(file), ".pcap")
		if index := strings.LastIndex(base, "-"); index >= 0 {
			base = base[:index]
		}
		groups[base] = append(groups[base], file)
	}
	var keys []string
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		sort.Strings(groups[key])
		if err = replayPacketFiles(ctx, s, p, groups[key], "pcap:"+key); err != nil {
			p.wg.Wait()
			return s.stats, err
		}
		p.wg.Wait()
	}
	if err = replayEvents(ctx, dir, s, p); err != nil {
		p.finish()
		return s.stats, err
	}
	p.finish()
	if err = stopIndex(); err != nil {
		return s.stats, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fatal != nil {
		return s.stats, s.fatal
	}
	if _, err = db.Exec(`CREATE TABLE reconstruction(id INTEGER PRIMARY KEY, stats BLOB, gaps BLOB)`); err != nil {
		return s.stats, err
	}
	stats, _ := json.Marshal(s.stats)
	gaps, _ := json.Marshal(s.gaps)
	_, err = db.Exec("INSERT INTO reconstruction VALUES(1,?,?)", stats, gaps)
	return s.stats, err
}

type eventSource struct {
	backend   string
	target    session.Target
	frames    Frames
	iis       *iisAssembler
	uncertain bool
	last      time.Time
}

func replayEvents(ctx context.Context, dir string, s *Store, p *HTTPProcessor) error {
	file, err := os.Open(filepath.Join(dir, "tls", "stream.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	sources := map[string]*eventSource{}
	finish := func(key string, source *eventSource) error {
		source.frames.expire(source.last, true, p, "")
		p.invalidatePrefix("tls:"+key+"/", "probe_source_ended")
		if source.iis != nil {
			return source.iis.finish()
		}
		return nil
	}
	defer func() {
		for key, source := range sources {
			if err := finish(key, source); err != nil {
				s.fail(err)
			}
		}
	}()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 65536), 4<<20)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var event session.RawEvent
		if err = json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("raw TLS event: %w", err)
		}
		if event.Version != 1 || event.Source == "" {
			return errors.New("unsupported raw TLS event schema")
		}
		if event.Type == "source" {
			if event.Target == nil {
				return errors.New("raw TLS source lacks target metadata")
			}
			if old := sources[event.Source]; old != nil {
				return errors.New("duplicate raw TLS source generation")
			}
			if len(sources) >= 1024 {
				return errors.New("too many active raw TLS source generations")
			}
			source := &eventSource{backend: event.Backend, target: *event.Target, last: event.Time}
			if event.Backend == "iis" {
				source.iis = &iisAssembler{store: s, target: *event.Target}
			}
			sources[event.Source] = source
			s.mu.Lock()
			if len(s.stats.Targets) >= 1024 {
				s.stats.Targets = s.stats.Targets[1:]
			}
			s.stats.Targets = append(s.stats.Targets, *event.Target)
			s.mu.Unlock()
			continue
		}
		source := sources[event.Source]
		if source == nil {
			return errors.New("raw TLS event references unknown source")
		}
		source.last = event.Time
		key := event.Source + "/" + event.Connection
		switch event.Type {
		case "end":
			if err = finish(event.Source, source); err != nil {
				return err
			}
			delete(sources, event.Source)
		case "loss":
			if err = finish(event.Source, source); err != nil {
				return err
			}
			source.uncertain = true
			s.gap(source.backend, event.Source, "recorded_probe_loss", "events", event.Count)
		case "close":
			source.frames.expire(event.Time, true, p, key)
			p.invalidate("tls:"+key, "recorded_connection_close")
		case "iis":
			if event.IIS == nil || source.iis == nil {
				return errors.New("invalid IIS raw event")
			}
			if err = source.iis.ingest(*event.IIS); err != nil {
				return err
			}
		case "data":
			if event.Direction != "read" && event.Direction != "write" {
				return errors.New("invalid raw event direction")
			}
			source.frames.expire(event.Time, false, p, "")
			source.frames.ingest(key+event.Direction, event.Data, frameContext{first: event.Time, updated: event.Time, connection: key, client: event.Client, local: event.Local, backend: replayBackend(source.backend), service: source.target.Service, pid: source.target.PID, targetID: source.target.ID, incomplete: event.Incomplete || source.uncertain}, false, p)
		default:
			return fmt.Errorf("unknown raw TLS event type %q", event.Type)
		}
	}
	return scanner.Err()
}

func replayBackend(backend string) string {
	switch backend {
	case "ecapture":
		return "openssl"
	case "java":
		return "java-agent"
	default:
		return backend
	}
}
