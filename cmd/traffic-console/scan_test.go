package main

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// sweepScanner is the original full-sweep SCAN-001 tracker. The heap-based
// tracker must produce the same alerts and state for any transaction order.
type sweepScanner struct {
	clients map[string]*scanState
}

func (scans *sweepScanner) scan(t Transaction, scanWindow time.Duration, scanThreshold int) *Alert {
	if t.Status == 0 {
		return nil
	}
	host, _, e := net.SplitHostPort(t.Client)
	if e != nil || host == "unknown" {
		return nil
	}
	now := t.Time
	for ip, s := range scans.clients {
		for path, x := range s.paths {
			if now.Sub(x.when) > scanWindow {
				delete(s.paths, path)
			}
		}
		if len(s.paths) == 0 {
			delete(scans.clients, ip)
		}
	}
	s := scans.clients[host]
	if s == nil {
		if len(scans.clients) >= 2000 {
			return nil
		}
		s = &scanState{paths: map[string]scanPath{}}
		scans.clients[host] = s
	}
	path := strings.SplitN(t.URL, "?", 2)[0]
	if _, ok := s.paths[path]; !ok && len(s.paths) >= 1000 {
		return nil
	}
	s.paths[path] = scanPath{now, t.Status}
	missing := 0
	for _, x := range s.paths {
		if x.status == 404 {
			missing++
		}
	}
	if len(s.paths) >= scanThreshold && missing*2 >= len(s.paths) && now.Sub(s.lastAlert) >= scanWindow {
		s.lastAlert = now
		return &Alert{Rule: "SCAN-001", Version: 1, Severity: "medium", Field: "path-window", Match: fmt.Sprintf("%d distinct paths, %d HTTP 404 within %s", len(s.paths), missing, scanWindow)}
	}
	return nil
}

func TestScanMatchesFullSweep(t *testing.T) {
	base := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name                       string
		steps, clients, paths      int
		window                     time.Duration
		maxStep, backStep, backOdd time.Duration
		threshold                  int
		fullClients, fullPaths     bool
	}{
		// Clients come and go inside a short window; time occasionally runs backwards.
		{name: "short window", steps: 15000, clients: 300, paths: 40, window: time.Minute, maxStep: 40 * time.Millisecond, backStep: 5 * time.Second, threshold: 20},
		// A long window keeps every client, so the 2000-client cap rejects newcomers.
		{name: "client cap", steps: 6000, clients: 2600, paths: 3, window: time.Hour, maxStep: 100 * time.Millisecond, backStep: time.Second, threshold: 2, fullClients: true},
		// One client walks far more than 1000 distinct paths.
		{name: "path cap", steps: 4000, clients: 2, paths: 3000, window: time.Hour, maxStep: 10 * time.Millisecond, backStep: time.Second, threshold: 20, fullPaths: true},
		// Few paths hit at a high rate leave many superseded sightings to compact.
		{name: "hot paths", steps: 30000, clients: 3, paths: 4, window: time.Minute, maxStep: 2 * time.Millisecond, backStep: 0, threshold: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := rand.New(rand.NewSource(int64(len(test.name))))
			want := &sweepScanner{clients: map[string]*scanState{}}
			got := &scanTracker{clients: map[string]*scanState{}}
			now := base
			alerts, fullClients, fullPaths := 0, false, false
			for step := range test.steps {
				now = now.Add(time.Duration(r.Int63n(int64(test.maxStep) + 1)))
				if test.backStep > 0 && r.Intn(50) == 0 {
					now = now.Add(-time.Duration(r.Int63n(int64(test.backStep))))
				}
				status := 200
				switch r.Intn(4) {
				case 0, 1:
					status = 404
				case 2:
					if r.Intn(10) == 0 {
						status = 0
					}
				}
				client := fmt.Sprintf("198.51.%d.%d:%d", r.Intn(test.clients)/250, r.Intn(test.clients)%250, 1000+r.Intn(5))
				if r.Intn(200) == 0 {
					client = "unknown:1"
				}
				record := Transaction{Time: now, Client: client, URL: fmt.Sprintf("/p/%d?x=%d", r.Intn(test.paths), step), Status: status}
				a, b := want.scan(record, test.window, test.threshold), scanWithState(record, got, test.window, test.threshold)
				if !reflect.DeepEqual(a, b) {
					t.Fatalf("step %d: alert %+v, want %+v", step, b, a)
				}
				if a != nil {
					alerts++
				}
				fullClients = fullClients || len(want.clients) == 2000
				for _, s := range want.clients {
					fullPaths = fullPaths || len(s.paths) == 1000
				}
			}
			if alerts == 0 || fullClients != test.fullClients || fullPaths != test.fullPaths {
				t.Fatalf("scenario not exercised: %d alerts, client cap %v, path cap %v", alerts, fullClients, fullPaths)
			}
			if len(got.clients) != len(want.clients) {
				t.Fatalf("clients %d, want %d", len(got.clients), len(want.clients))
			}
			tracked := 0
			for host, w := range want.clients {
				g := got.clients[host]
				if g == nil || !reflect.DeepEqual(g.paths, w.paths) || !g.lastAlert.Equal(w.lastAlert) {
					t.Fatalf("client %s differs", host)
				}
				missing := 0
				for _, x := range w.paths {
					if x.status == 404 {
						missing++
					}
				}
				if g.missing != missing {
					t.Fatalf("client %s missing %d, want %d", host, g.missing, missing)
				}
				tracked += len(w.paths)
			}
			if got.tracked != tracked {
				t.Fatalf("tracked %d, want %d", got.tracked, tracked)
			}
			if len(got.seen) > 2*tracked+4096+1 {
				t.Fatalf("expiry heap holds %d sightings for %d paths", len(got.seen), tracked)
			}
		})
	}
}

// BenchmarkScanManyClients is the shape that made the full sweep dominate
// local analysis: about a thousand active clients inside one window.
func BenchmarkScanManyClients(b *testing.B) {
	records := make([]Transaction, 15000)
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	r := rand.New(rand.NewSource(1))
	for i := range records {
		now = now.Add(2 * time.Millisecond)
		records[i] = Transaction{Time: now, Client: fmt.Sprintf("192.168.%d.%d:80", r.Intn(4), r.Intn(250)), URL: fmt.Sprintf("/p/%d", r.Intn(12)), Status: 200}
	}
	b.ResetTimer()
	for b.Loop() {
		scanner := &scanTracker{clients: map[string]*scanState{}}
		for _, record := range records {
			scanWithState(record, scanner, time.Minute, 20)
		}
	}
}

func TestScanCountsSkippedTransactions(t *testing.T) {
	scanner := &scanTracker{clients: map[string]*scanState{}}
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	for i := range maxScanClients + 3 {
		scanWithState(Transaction{Time: now, Client: fmt.Sprintf("10.%d.%d.1:80", i/250, i%250), URL: "/", Status: 404}, scanner, time.Hour, 20)
	}
	for i := range maxScanPaths + 5 {
		scanWithState(Transaction{Time: now, Client: "10.0.0.1:80", URL: fmt.Sprintf("/p/%d", i), Status: 404}, scanner, time.Hour, 20)
	}
	// Status 0 and unknown clients are never tracked, so they are not skips.
	scanWithState(Transaction{Time: now, Client: "10.99.0.1:80", URL: "/", Status: 0}, scanner, time.Hour, 20)
	scanWithState(Transaction{Time: now, Client: "unknown:0", URL: "/", Status: 404}, scanner, time.Hour, 20)
	// The first client already holds "/", so maxScanPaths-1 new paths fit.
	if want := (scanSkipped{Clients: 3, Paths: 6}); scanner.skipped != want {
		t.Fatalf("skipped %+v, want %+v", scanner.skipped, want)
	}
}
