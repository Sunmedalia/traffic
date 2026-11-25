package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
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

func TestWebhookDialAddressPolicy(t *testing.T) {
	for _, tc := range []struct {
		ip                            string
		allowPrivate, requireLoopback bool
		wantError                     string
	}{
		{ip: "127.9.1.2", requireLoopback: true},
		{ip: "::1", requireLoopback: true},
		{ip: "::ffff:127.0.0.1", requireLoopback: true},
		{ip: "0.7.0.1", allowPrivate: true, wantError: "not permitted"},
		{ip: "::", allowPrivate: true, wantError: "not permitted"},
		{ip: "169.254.169.254", allowPrivate: true, wantError: "not permitted"},
		{ip: "::ffff:169.254.2.3", allowPrivate: true, wantError: "not permitted"},
		{ip: "fe80::1%eth0", allowPrivate: true, wantError: "not permitted"},
		{ip: "fd00:ec2::254", allowPrivate: true, wantError: "not permitted"},
		{ip: "100.100.100.200", allowPrivate: true, wantError: "not permitted"},
		{ip: "10.1.2.3", wantError: "--allow-private-webhook"},
		{ip: "::ffff:172.31.1.2", wantError: "--allow-private-webhook"},
		{ip: "fd00::1", wantError: "--allow-private-webhook"},
		{ip: "192.168.1.1", allowPrivate: true},
		{ip: "fd00::1", allowPrivate: true},
		{ip: "10.1.2.3", allowPrivate: true, requireLoopback: true, wantError: "requires HTTPS"},
		{ip: "8.8.8.8", requireLoopback: true, wantError: "requires HTTPS"},
		{ip: "8.8.8.8"},
		{ip: "2001:4860::8888"},
	} {
		err := checkWebhookIP(netip.MustParseAddr(tc.ip), tc.allowPrivate, tc.requireLoopback)
		if tc.wantError == "" && err != nil || tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
			t.Errorf("IP %s (private=%t, loopback-only=%t): got %v, want %q", tc.ip, tc.allowPrivate, tc.requireLoopback, err, tc.wantError)
		}
	}
}

func TestWebhookRejectsBearerOverNonLoopbackHTTP(t *testing.T) {
	endpoint := "http://192.168.7.1/alerts"
	privateWebhookEndpoint.Store(&endpoint)
	t.Cleanup(func() { privateWebhookEndpoint.CompareAndSwap(&endpoint, nil) })
	webhook := newAlertWebhook(&deliveryReport{}, endpoint, "secret")
	defer webhook.close()
	err := webhook.deliver(context.Background(), []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "requires HTTPS") {
		t.Fatalf("plain HTTP with a token and the private exception: %v", err)
	}
}

func TestWebhookDialRechecksChangingDNSAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	var answerMode atomic.Int32
	go func() {
		var buf [512]byte
		for {
			n, peer, err := dns.ReadFrom(buf[:])
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buf[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			response := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true},
				Questions: query.Questions,
			}
			if question := query.Questions[0]; question.Type == dnsmessage.TypeA {
				ip := [4]byte{127, 0, 0, 1}
				switch answerMode.Load() {
				case 1:
					ip = [4]byte{169, 254, 169, 254}
				case 2:
					ip = [4]byte{}
				}
				response.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: question.Class},
					Body:   &dnsmessage.AResource{A: ip},
				}}
			}
			answer, err := response.Pack()
			if err == nil {
				_, _ = dns.WriteTo(answer, peer)
			}
		}
	}()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", dns.LocalAddr().String())
	}}
	dial := webhookDialContext(resolver, true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	address := net.JoinHostPort("webhook-test.invalid.", port)
	conn, err := dial(ctx, "tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	for i, ip := range []string{"169.254.169.254", "0.0.0.0"} {
		answerMode.Store(int32(i + 1))
		conn, err := dial(ctx, "tcp4", address)
		if conn != nil {
			conn.Close()
		}
		if err == nil || !strings.Contains(err.Error(), ip+" is not permitted") {
			t.Fatalf("rebound address %s was not rejected at dial time: %v", ip, err)
		}
	}
}
