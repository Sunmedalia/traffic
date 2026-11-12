package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

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

type alertWebhook struct {
	queue           chan []byte
	done            chan struct{}
	cancel          context.CancelFunc
	client          *http.Client
	endpoint, token string
	store           *Store
	mu              sync.Mutex
	closed          bool
	queuedBytes     int
}

func newAlertWebhook(s *Store, endpoint, token string) *alertWebhook {
	ctx, cancel := context.WithCancel(context.Background())
	w := &alertWebhook{
		queue: make(chan []byte, 128), done: make(chan struct{}), cancel: cancel,
		client:   &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
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
