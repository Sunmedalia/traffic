package main

import (
	"bytes"
	"container/list"
	"strings"
	"sync"
	"time"
)

const requestCacheBudget = 16 << 20

type requestCacheEntry struct {
	record Transaction
	size   int
	added  time.Time
}

// This cache is an accelerator only: requests are still persisted immediately.
// Immutable owned snapshots keep caller buffers out of the cache. Eviction never
// removes SQLite evidence, so a response can always use the existing fallback.
type requestCache struct {
	mu     sync.Mutex
	items  map[string]*list.Element
	order  list.List
	bytes  int
	budget int
}

func cloneRequest(t Transaction) (Transaction, int) {
	t.Time = t.Time.Round(0)
	t.Request = bytes.Clone(t.Request)
	t.Response = bytes.Clone(t.Response)
	t.IntegrityReasons = append([]string(nil), t.IntegrityReasons...)
	t.Alerts = append([]Alert(nil), t.Alerts...)
	size := 1024 + len(t.Request) + len(t.Response)
	for _, field := range []*string{&t.ID, &t.Protocol, &t.Backend, &t.LocalEndpoint, &t.Service, &t.TargetID, &t.Host, &t.Source, &t.Client, &t.PeerClient, &t.ClientSource, &t.Connection, &t.Method, &t.URL} {
		*field = strings.Clone(*field)
		size += len(*field)
	}
	for i := range t.IntegrityReasons {
		t.IntegrityReasons[i] = strings.Clone(t.IntegrityReasons[i])
		size += 32 + len(t.IntegrityReasons[i])
	}
	for i := range t.Alerts {
		a := &t.Alerts[i]
		size += 160
		for _, field := range []*string{&a.Rule, &a.Severity, &a.Field, &a.Match, &a.View} {
			*field = strings.Clone(*field)
			size += len(*field)
		}
	}
	cloneHeaders := func(source map[string][]string) map[string][]string {
		if source == nil {
			return nil
		}
		result := make(map[string][]string, len(source))
		for key, values := range source {
			copied := make([]string, len(values))
			size += 128 + len(key)
			for i, value := range values {
				copied[i] = strings.Clone(value)
				size += 32 + len(value)
			}
			result[strings.Clone(key)] = copied
		}
		return result
	}
	t.RequestTrailers = cloneHeaders(t.RequestTrailers)
	t.ResponseTrailers = cloneHeaders(t.ResponseTrailers)
	return t, size
}
func (c *requestCache) remove(e *list.Element) {
	entry := e.Value.(requestCacheEntry)
	delete(c.items, entry.record.ID)
	c.bytes -= entry.size
	c.order.Remove(e)
}
func (c *requestCache) expire(now time.Time) {
	for e := c.order.Front(); e != nil; e = c.order.Front() {
		if now.Sub(e.Value.(requestCacheEntry).added) < time.Minute {
			return
		}
		c.remove(e)
	}
}
func (c *requestCache) get(id string) (Transaction, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(time.Now())
	if e := c.items[id]; e != nil {
		v := e.Value.(requestCacheEntry)
		return v.record, true
	}
	return Transaction{}, false
}
func (c *requestCache) put(t Transaction) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(time.Now())
	if e := c.items[t.ID]; e != nil {
		c.remove(e)
	}
	if len(t.Response) > 0 || len(t.Request) == 0 || t.Method == "" || t.Incomplete {
		return
	}
	budget := c.budget
	if budget == 0 {
		budget = requestCacheBudget
	}
	// Refuse oversized messages before allocating their copy.
	if len(t.Request)+len(t.Response)+1024 > budget {
		return
	}
	copied, size := cloneRequest(t)
	if size > budget {
		return
	}
	for c.order.Len() > 0 && (c.bytes+size > budget || c.order.Len() >= 2000) {
		c.remove(c.order.Front())
	}
	if c.items == nil {
		c.items = make(map[string]*list.Element)
	}
	c.items[t.ID] = c.order.PushBack(requestCacheEntry{copied, size, time.Now()})
	c.bytes += size
}
func (s *Store) restorePending(record *Transaction) error {
	if cached, ok := s.requests.get(record.ID); ok {
		copied, _ := cloneRequest(cached)
		*record = copied
		return nil
	}
	return s.restore(record)
}
