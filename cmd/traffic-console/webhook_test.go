package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestWebhookRetryAndUpdatedAlertIdentity(t *testing.T) {
	original := rules
	defer func() { rules = original }()
	rules = []Rule{
		{ID: "A", Version: 1, Severity: "high", Field: "response.body", Pattern: "first"},
		{ID: "B", Version: 1, Severity: "high", Field: "response.body", Pattern: "second"},
	}
	if err := compileRules(rules); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var payloads, keys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("invalid webhook request")
		}
		mu.Lock()
		payloads = append(payloads, string(data))
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		count := len(payloads)
		mu.Unlock()
		if count == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	store := &deliveryReport{}
	webhook := newAlertWebhook(store, server.URL, "test-token")
	defer webhook.close()
	webhook.enqueue([]byte(`{"id":"same","alert":{"rule":"A"}}`))
	webhook.enqueue([]byte(`{"id":"same","alert":{"rule":"B"}}`))
	webhook.close()
	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 3 || payloads[0] != payloads[1] || keys[0] == "" || keys[0] != keys[1] || keys[1] == keys[2] || !strings.Contains(payloads[2], `"rule":"B"`) {
		t.Fatalf("bad deliveries %v %v", payloads, keys)
	}
	if store.stats.AlertDelivered != 2 || store.stats.AlertDeliveryFailed != 0 {
		t.Fatalf("bad counters %+v", store.stats)
	}
}

func TestWebhookRejectsRedirectAndCountsFailure(t *testing.T) {
	reached := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer redirect.Close()
	store := &deliveryReport{}
	webhook := newAlertWebhook(store, redirect.URL, "test-token")
	webhook.enqueue([]byte(`{"id":"test"}`))
	webhook.close()
	if reached || store.stats.AlertDeliveryFailed != 1 {
		t.Fatalf("redirect followed or missing failure %+v", store.stats)
	}
	for _, endpoint := range []string{"file:///tmp/test", "http://user:secret@localhost/", "http://", "https://host/#fragment"} {
		if validateWebhook(endpoint) == nil {
			t.Errorf("accepted %s", endpoint)
		}
	}
}

func TestWebhookQueueBounds(t *testing.T) {
	store := &deliveryReport{}
	webhook := &alertWebhook{queue: make(chan []byte, 1), store: store}
	webhook.enqueue([]byte("first"))
	webhook.enqueue([]byte("second"))
	if store.stats.AlertDeliveryDropped != 1 || webhook.queuedBytes != 5 {
		t.Fatalf("queue bound failed %+v", store.stats)
	}
	webhook.enqueue(make([]byte, (4<<20)+1))
	if store.stats.AlertDeliveryDropped != 2 || webhook.queuedBytes != 5 {
		t.Fatalf("byte bound failed %+v", store.stats)
	}
}
