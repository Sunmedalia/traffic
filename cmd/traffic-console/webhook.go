package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The CLI grants the exception to its configured endpoint for one analysis.
var privateWebhookEndpoint atomic.Pointer[string]

var (
	ec2MetadataIPv6      = netip.MustParseAddr("fd00:ec2::254")
	ecsMetadataIPv4      = netip.MustParseAddr("100.100.100.200")
	cgnatPrefix          = netip.MustParsePrefix("100.64.0.0/10")
	nat64WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalPrefix     = netip.MustParsePrefix("64:ff9b:1::/48")
)

func isLoopbackHost(host string) bool {
	trimmed := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if trimmed == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().IsLoopback()
	}
	return false
}

func validateWebhook(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("--alert-webhook requires an HTTP(S) URL without userinfo or fragment")
	}
	return nil
}

func checkWebhookIP(ip netip.Addr, allowPrivate, requireLoopback bool) error {
	return checkWebhookIPForHost(ip, true, allowPrivate, requireLoopback)
}

func checkWebhookIPForHost(ip netip.Addr, loopbackHost, allowPrivate, requireLoopback bool) error {
	ip = ip.Unmap().WithZone("")
	if ip.IsLoopback() {
		if loopbackHost {
			return nil
		}
		if requireLoopback {
			return fmt.Errorf("TRAFFIC_WEBHOOK_TOKEN requires HTTPS for non-loopback webhook destinations")
		}
		if !allowPrivate {
			return fmt.Errorf("private webhook destination %s requires --allow-private-webhook", ip)
		}
		return nil
	}
	// Global unicast excludes link-local, unspecified and multicast.
	// The rest of IPv4's zero network, cloud metadata, and NAT64 prefixes need explicit checks.
	if !ip.IsGlobalUnicast() || (ip.Is4() && ip.As4()[0] == 0) ||
		ip == ec2MetadataIPv6 || ip == ecsMetadataIPv4 ||
		nat64WellKnownPrefix.Contains(ip) || nat64LocalPrefix.Contains(ip) {
		return fmt.Errorf("webhook destination %s is not permitted", ip)
	}
	if requireLoopback {
		return fmt.Errorf("TRAFFIC_WEBHOOK_TOKEN requires HTTPS for non-loopback webhook destinations")
	}
	if (ip.IsPrivate() || cgnatPrefix.Contains(ip)) && !allowPrivate {
		return fmt.Errorf("private webhook destination %s requires --allow-private-webhook", ip)
	}
	return nil
}

func webhookDialContext(resolver *net.Resolver, allowPrivate, requireLoopback bool) func(context.Context, string, string) (net.Conn, error) {
	dialer := net.Dialer{KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		// Validate before passing a numeric address to DialContext. Go can
		// rewrite an unspecified dial address to loopback before net.Dialer.Control.
		var ips []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{ip}
		} else {
			family := "ip"
			switch network {
			case "tcp4":
				family = "ip4"
			case "tcp6":
				family = "ip6"
			}
			ips, err = resolver.LookupNetIP(ctx, family, host)
			if err != nil {
				return nil, err
			}
		}
		loopbackHost := isLoopbackHost(host)
		var lastErr error
		allowed := ips[:0]
		for _, ip := range ips {
			if err := checkWebhookIPForHost(ip, loopbackHost, allowPrivate, requireLoopback); err != nil {
				lastErr = err
			} else {
				allowed = append(allowed, ip)
			}
		}

		deadline, _ := ctx.Deadline()
		for i, ip := range allowed {
			// Share the connection budget so an unreachable address leaves
			// time for later candidates. A numeric dial never resolves again.
			attempt, cancel := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(allowed)-i))
			conn, err := dialer.DialContext(attempt, network, net.JoinHostPort(ip.String(), port))
			cancel()
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("webhook destination has no IP addresses")
		}
		return nil, lastErr
	}
}

type alertWebhook struct {
	queue           chan []byte
	done            chan struct{}
	cancel          context.CancelFunc
	client          *http.Client
	endpoint, token string
	store           *deliveryReport
	mu              sync.Mutex
	closed          bool
	queuedBytes     int
}

func newAlertWebhook(s *deliveryReport, endpoint, token string) *alertWebhook {
	ctx, cancel := context.WithCancel(context.Background())
	parsed, _ := url.Parse(endpoint)
	requireLoopback := token != "" && (parsed == nil || parsed.Scheme != "https")
	privateEndpoint := privateWebhookEndpoint.Load()
	allowPrivate := privateEndpoint != nil && *privateEndpoint == endpoint
	transport := &http.Transport{
		// Direct connections make the dial policy apply to the webhook
		// destination itself, even when HTTP(S)_PROXY is set.
		DialContext:         webhookDialContext(net.DefaultResolver, allowPrivate, requireLoopback),
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 3 * time.Second,
	}
	w := &alertWebhook{
		queue: make(chan []byte, 128), done: make(chan struct{}), cancel: cancel,
		client:   &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		endpoint: endpoint, token: token, store: s,
	}
	go func() {
		defer close(w.done)
		for payload := range w.queue {
			w.mu.Lock()
			w.queuedBytes -= len(payload)
			w.mu.Unlock()
			err := w.deliver(ctx, payload)
			w.store.mu.Lock()
			if err != nil {
				w.store.stats.AlertDeliveryFailed++
			} else {
				w.store.stats.AlertDelivered++
			}
			w.store.mu.Unlock()
			if err != nil {
				w.store.problem(fmt.Errorf("alert webhook delivery failed: %w", err))
			}
		}
	}()
	return w
}

func (w *alertWebhook) enqueue(payload []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	if w.queuedBytes+len(payload) > 4<<20 {
		w.store.mu.Lock()
		w.store.stats.AlertDeliveryDropped++
		w.store.mu.Unlock()
		return
	}
	select {
	case w.queue <- payload:
		w.queuedBytes += len(payload)
	default:
		w.store.mu.Lock()
		w.store.stats.AlertDeliveryDropped++
		w.store.mu.Unlock()
	}
}

func (w *alertWebhook) deliver(ctx context.Context, payload []byte) error {
	key := fmt.Sprintf("%x", sha256.Sum256(payload))
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		if w.token != "" {
			request.Header.Set("Authorization", "Bearer "+w.token)
		}
		response, err := w.client.Do(request)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				return nil
			}
			err = fmt.Errorf("HTTP %d", response.StatusCode)
			if response.StatusCode != 429 && response.StatusCode < 500 {
				return err
			}
		}
		// Keep destination credentials and query parameters out of persisted errors.
		last = err
		if status, ok := err.(*url.Error); ok {
			last = fmt.Errorf("attempt %d: %v", attempt+1, status.Err)
		}
		if attempt == 2 {
			break
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}

// Drain during normal shutdown, then cancel remaining network calls after five seconds.
func (w *alertWebhook) close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.queue)
	w.mu.Unlock()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-w.done:
	case <-timer.C:
		w.cancel()
		<-w.done
	}
	w.cancel()
	w.client.CloseIdleConnections()
}

// Delivery counters are local analysis output; capture status remains untouched.
type deliveryReport struct {
	mu    sync.Mutex
	stats Stats
}

func (s *deliveryReport) problem(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.stats.Errors) < 100 {
		s.stats.Errors = append(s.stats.Errors, err.Error())
	}
}
