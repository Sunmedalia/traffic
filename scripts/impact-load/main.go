// A standalone HTTP/1 load worker for scripts/impact.py --load-command.
// Configuration arrives on stdin; stdout contains the request ledger and result.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type config struct {
	URL         string  `json:"url"`
	Rate        float64 `json:"rate"`
	Seconds     float64 `json:"seconds"`
	Concurrency int     `json:"concurrency"`
	BodyBytes   int     `json:"body_bytes"`
	RunID       string  `json:"run_id"`
	Phase       string  `json:"phase"`
}
type requestEvent struct {
	Kind      string  `json:"kind"`
	ID        string  `json:"id"`
	Phase     string  `json:"phase"`
	Sent      *bool   `json:"sent,omitempty"`
	SentAt    float64 `json:"sent_at_unix,omitempty"`
	ElapsedMS float64 `json:"elapsed_ms,omitempty"`
	Success   bool    `json:"success"`
	Error     string  `json:"error"`
}
type histogram struct {
	bins  map[int]int
	count int
}

var bucketStep = math.Log1p(.001)

func (h *histogram) add(value float64) {
	bucket := int(math.Ceil(math.Log1p(value*1000) / bucketStep))
	h.bins[bucket]++
	h.count++
}
func (h *histogram) quantile(fraction float64) float64 {
	keys := make([]int, 0, len(h.bins))
	for key := range h.bins {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	rank := int(float64(h.count-1) * fraction)
	for _, key := range keys {
		rank -= h.bins[key]
		if rank < 0 {
			return math.Expm1(float64(key)*bucketStep) / 1000
		}
	}
	return 0
}
func run(input io.Reader, output io.Writer) error {
	var cfg config
	if err := json.NewDecoder(io.LimitReader(input, 1<<20)).Decode(&cfg); err != nil {
		return err
	}
	if cfg.Rate <= 0 || math.IsNaN(cfg.Rate) || math.IsInf(cfg.Rate, 0) || cfg.Seconds <= 0 || math.IsNaN(cfg.Seconds) || math.IsInf(cfg.Seconds, 0) || cfg.Concurrency < 1 || cfg.Concurrency > 4096 || cfg.BodyBytes < 0 || cfg.BodyBytes > 1<<20 {
		return fmt.Errorf("invalid load configuration")
	}
	probe, err := http.NewRequest("POST", cfg.URL, nil)
	if err != nil {
		return err
	}
	if probe.URL.Hostname() == "" || probe.URL.User != nil || probe.URL.Fragment != "" || (probe.URL.Scheme != "https" && probe.URL.Scheme != "http") {
		return fmt.Errorf("invalid load URL")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}, DisableCompression: true, MaxIdleConns: cfg.Concurrency, MaxIdleConnsPerHost: cfg.Concurrency, MaxConnsPerHost: cfg.Concurrency}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	jobs := make(chan int, cfg.Concurrency)
	events := make(chan requestEvent, 2*cfg.Concurrency)
	var workers sync.WaitGroup
	padding := strings.Repeat("x", cfg.BodyBytes)
	for worker := 0; worker < cfg.Concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				marker := fmt.Sprintf("%s-%s-%d", cfg.RunID, cfg.Phase, index)
				body, _ := json.Marshal(struct {
					Marker  string `json:"marker"`
					Message string `json:"message"`
				}{marker, padding})
				req, _ := http.NewRequest("POST", cfg.URL, strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Traffic-Test-ID", marker)
				start := time.Now()
				event := requestEvent{Kind: "request", ID: marker, Phase: cfg.Phase, SentAt: float64(start.UnixNano()) / 1e9}
				resp, err := client.Do(req)
				if err != nil {
					event.Error = err.Error()
				} else {
					data, readErr := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
					_ = resp.Body.Close()
					var decoded struct {
						Body string `json:"body"`
					}
					event.Success = readErr == nil && len(data) <= 2<<20 && resp.StatusCode == 200 && json.Unmarshal(data, &decoded) == nil && decoded.Body == string(body)
					if readErr != nil {
						event.Error = readErr.Error()
					} else if !event.Success {
						event.Error = "invalid_echo_response"
					}
				}
				event.ElapsedMS = float64(time.Since(start)) / float64(time.Millisecond)
				events <- event
			}
		}()
	}
	writer := bufio.NewWriterSize(output, 64<<10)
	encoder := json.NewEncoder(writer)
	stats := struct {
		requests, errors, dropped int
		hist                      histogram
	}{hist: histogram{bins: map[int]int{}}}
	writeDone := make(chan error, 1)
	go func() {
		var failure error
		for event := range events {
			if event.Sent != nil && !*event.Sent {
				stats.dropped++
			} else {
				stats.requests++
				if !event.Success {
					stats.errors++
				}
				stats.hist.add(event.ElapsedMS)
			}
			if failure == nil {
				failure = encoder.Encode(event)
			}
		}
		writeDone <- failure
	}()
	start := time.Now()
	total := int(math.Ceil(cfg.Rate * cfg.Seconds))
	unsent := false
	for index := 0; index < total; index++ {
		due := start.Add(time.Duration(float64(time.Second) * float64(index) / cfg.Rate))
		if delay := time.Until(due); delay > 0 {
			time.Sleep(delay)
		}
		select {
		case jobs <- index:
		default:
			events <- requestEvent{Kind: "request", ID: fmt.Sprintf("%s-%s-%d", cfg.RunID, cfg.Phase, index), Phase: cfg.Phase, Sent: &unsent, Error: "generator_capacity"}
		}
	}
	close(jobs)
	workers.Wait()
	close(events)
	if err := <-writeDone; err != nil {
		return err
	}
	if stats.requests == 0 {
		return fmt.Errorf("no completed requests")
	}
	duration := time.Since(start).Seconds()
	workerInfo := map[string]string{"platform": runtime.GOOS + "/" + runtime.GOARCH, "go": runtime.Version()}
	if path, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(path); err == nil {
			sum := sha256.Sum256(data)
			workerInfo["binary_sha256"] = hex.EncodeToString(sum[:])
		}
	}
	result := map[string]any{"kind": "result", "requests": stats.requests, "errors": stats.errors, "generator_dropped": stats.dropped, "successful_rps": float64(stats.requests-stats.errors) / duration, "load_duration_seconds": duration, "p95_ms": stats.hist.quantile(.95), "p99_ms": stats.hist.quantile(.99), "latency_quantile_error": "upper bound; <=0.1% plus 1us", "worker": workerInfo}
	if err := encoder.Encode(result); err != nil {
		return err
	}
	return writer.Flush()
}
func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
