package main

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestPendingCacheOwnsBuffersAndFallsBackToSQLite(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	t1 := Transaction{ID: "request", Time: time.Now().UTC(), Method: "POST", URL: "/?q=%2527%2520or%25201%253D1", Request: []byte("POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 6\r\n\r\nneedle"), RequestTrailers: map[string][]string{"X-End": {"a"}}}
	if err = s.save(t1); err != nil {
		t.Fatal(err)
	}
	want := Transaction{ID: t1.ID}
	if err = s.restore(&want); err != nil {
		t.Fatal(err)
	}
	t1.Request[0] = 'X'
	t1.RequestTrailers["X-End"][0] = "changed"
	got := Transaction{ID: t1.ID}
	if err = s.restorePending(&got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cache aliased caller: %+v != %+v", got, want)
	}
	got.Request[0] = 'Y'
	got.RequestTrailers["X-End"][0] = "consumer"
	got = Transaction{ID: t1.ID}
	if err = s.restorePending(&got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("cache aliased restore output")
	}
	s.requests.mu.Lock()
	s.requests.remove(s.requests.order.Front())
	s.requests.mu.Unlock()
	got = Transaction{ID: t1.ID}
	if err = s.restorePending(&got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("eviction lost persisted request", err)
	}
}
func TestPendingCacheBudgetExpiryAndCompletedRemoval(t *testing.T) {
	var c requestCache
	c.budget = 4096
	for _, id := range []string{"a", "b", "c"} {
		c.put(Transaction{ID: id, Method: "POST", Request: bytes.Repeat([]byte("x"), 1400)}, 1)
	}
	if c.bytes > 4096 || c.order.Len() != 1 {
		t.Fatal("cache exceeded budget", c.bytes, c.order.Len())
	}
	if _, _, ok := c.get("a"); ok {
		t.Fatal("oldest request not evicted")
	}
	c.mu.Lock()
	e := c.order.Front()
	v := e.Value.(requestCacheEntry)
	v.added = time.Now().Add(-2 * time.Minute)
	e.Value = v
	c.mu.Unlock()
	if _, _, ok := c.get("c"); ok || c.bytes != 0 {
		t.Fatal("expired cache retained request")
	}
	c.put(Transaction{ID: "done", Method: "GET", Request: []byte("GET / HTTP/1.1\r\n\r\n")}, 1)
	c.put(Transaction{ID: "done", Method: "GET", Request: []byte("GET / HTTP/1.1\r\n\r\n"), Response: []byte("response")}, 1)
	if c.bytes != 0 {
		t.Fatal("completed request not released")
	}
}
func TestIncrementalDetectionMatchesFullDetection(t *testing.T) {
	if err := loadRules(""); err != nil {
		t.Fatal(err)
	}
	original := noDetect
	noDetect = false
	defer func() { noDetect = original }()
	for _, payload := range []string{"normal", "%2527%2520or%25201%253D1", "<script>alert(1)</script>", "${jndi:ldap://example/a}"} {
		previous := Transaction{URL: "/test?q=" + payload, Request: []byte("POST / HTTP/1.1\r\nHost: test\r\n\r\n" + payload)}
		previous.Alerts = detect(previous)
		current := previous
		current.Response = []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nroot:x:0:0:")
		if got, want := detectWithPrevious(current, &previous), detect(current); !reflect.DeepEqual(got, want) {
			t.Fatalf("changed detection for %q: %+v != %+v", payload, got, want)
		}
	}
}
