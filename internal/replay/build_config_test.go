package replay

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Sunmedalia/traffic/internal/index"
	"github.com/Sunmedalia/traffic/internal/session"
)

// buildConfigSession writes a raw TLS session served on port with one POST
// whose body is size bytes.
func buildConfigSession(t *testing.T, port, size int) string {
	t.Helper()
	dir := t.TempDir()
	manifest := fmt.Sprintf(`{"capture_mode":"raw","capture_ports":[%d],"local_addresses":["127.0.0.1"]}`, port)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "tls"), 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	local := fmt.Sprintf("127.0.0.1:%d", port)
	target := &session.Target{PID: 9, ID: "9:start", Service: "svc", Ports: []int{port}}
	body := bytes.Repeat([]byte("z"), size)
	request := append([]byte(fmt.Sprintf("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n", size)), body...)
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	for _, event := range []session.RawEvent{
		{Version: 1, Source: "s", Type: "source", Backend: "ecapture", Target: target, Time: now},
		{Version: 1, Source: "s", Type: "data", Connection: "c", Direction: "read", Data: request, Local: local, Client: "192.0.2.1:5", Time: now},
		{Version: 1, Source: "s", Type: "data", Connection: "c", Direction: "write", Data: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), Local: local, Client: "192.0.2.1:5", Time: now},
		{Version: 1, Source: "s", Type: "end", Time: now.Add(time.Second)},
	} {
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "tls", "stream.jsonl"), out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Decoder settings belong to each build: concurrent builds with different
// limits and ports run in parallel without seeing each other's settings, and
// nothing is left behind for a later build.
func TestConcurrentBuildsUseTheirOwnConfiguration(t *testing.T) {
	type run struct {
		dir          string
		port, limit  int
		stats        Stats
		err          error
		request      []byte
		truncated    bool
		transactions int
	}
	var runs []*run
	for i := 0; i < 8; i++ {
		port := []int{8443, 9443}[i%2]
		limit := []int{100, 1 << 20}[i/2%2]
		runs = append(runs, &run{dir: buildConfigSession(t, port, 4096), port: port, limit: limit})
	}
	var wg sync.WaitGroup
	for _, r := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := sql.Open(index.Driver, ":memory:")
			if err != nil {
				r.err = err
				return
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			if r.stats, r.err = Build(context.Background(), r.dir, db, Options{RequestLimit: r.limit, ResponseLimit: r.limit}); r.err != nil {
				return
			}
			var raw []byte
			if r.err = db.QueryRow("SELECT " + storedRecord + " FROM requests").Scan(&raw); r.err != nil {
				return
			}
			var record Transaction
			r.err = json.Unmarshal(raw, &record)
			r.request, r.truncated = record.Request, record.Truncated
		}()
	}
	wg.Wait()
	for _, r := range runs {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.stats.Transactions != 1 || r.truncated != (r.limit == 100) {
			t.Fatalf("port %d limit %d: %d transactions, truncated=%v", r.port, r.limit, r.stats.Transactions, r.truncated)
		}
		if r.limit == 100 && !bytes.HasSuffix(r.request, bytes.Repeat([]byte("z"), 100)) {
			t.Fatal("truncated body")
		}
	}
	if got := (&Store{}).requestLimit(); got != defaultRequestLimit {
		t.Fatal("unconfigured store limit", got)
	}
	if !(&Store{}).capturePort(443) || (&Store{}).capturePort(8443) || (&Store{}).capturesAllPorts() {
		t.Fatal("unconfigured store ports")
	}
}

func TestBuildStoresBodiesOutsideMetadata(t *testing.T) {
	dir := buildConfigSession(t, 443, 64)
	db, err := sql.Open(index.Driver, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = Build(context.Background(), dir, db, Options{RequestLimit: 1 << 20, ResponseLimit: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	var data, request, response []byte
	if err = db.QueryRow("SELECT data,request_raw,response_raw FROM requests").Scan(&data, &request, &response); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"request"`)) || bytes.Contains(data, []byte(`"response"`)) {
		t.Fatal("metadata carries bodies", string(data))
	}
	if !bytes.HasPrefix(request, []byte("POST /x ")) || string(response) != "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" {
		t.Fatal("raw bodies", string(request), string(response))
	}
	record, err := decodeStored(data, request, response)
	if err != nil || !bytes.Equal(record.Request, request) || record.Status != 200 {
		t.Fatal("decodeStored", err)
	}
}

func TestBuildHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, buildConfigSession(t, 443, 1), nil, Options{RequestLimit: 1, ResponseLimit: 1}); err != context.Canceled {
		t.Fatal(err)
	}
}
