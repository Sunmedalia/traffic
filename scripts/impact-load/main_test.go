package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkerHTTP1Ledger(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Errorf("worker negotiated %s", r.Proto)
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"body": string(data)})
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	cfg := config{URL: server.URL + "/api/echo?test=1", Rate: 20, Seconds: .25, Concurrency: 4, BodyBytes: 1024, RunID: "test", Phase: "baseline"}
	input, _ := json.Marshal(cfg)
	var output bytes.Buffer
	if err := run(bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	ids := map[string]bool{}
	completed := false
	for decoder.More() {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event["kind"] == "request" {
			id := event["id"].(string)
			if ids[id] || event["success"] != true || !strings.HasPrefix(id, "test-baseline-") {
				t.Fatal("invalid ledger", event)
			}
			ids[id] = true
		} else if event["kind"] == "result" {
			if completed || event["requests"] != float64(5) || event["errors"] != float64(0) || event["generator_dropped"] != float64(0) {
				t.Fatal(event)
			}
			completed = true
		} else {
			t.Fatal(event)
		}
	}
	if len(ids) != 5 || !completed {
		t.Fatal("missing request/result", ids, completed)
	}
}
