package replay

import (
	"container/list"
	"sync"
)

const (
	requestCacheBudget  = 16 << 20
	requestCacheEntries = 4096
)

type requestCacheEntry struct {
	record Transaction
	size   int
}

// requestCache parks HTTP/1.1 requests that wait for their response, so a
// paired transaction is written to SQLite once instead of once per direction.
// The cache owns each parked record: callers hand over buffers they no longer
// touch and take() transfers ownership back, so neither side copies.
//
// It is bounded by bytes and entries. A request that does not fit, or that the
// oldest-first eviction removes, is spilled to SQLite while c.mu is held. A
// take() for that ID therefore either finds the record in memory or runs after
// the spill and restores it from the same writer transaction.
type requestCache struct {
	mu      sync.Mutex
	items   map[string]*list.Element
	order   list.List
	bytes   int
	budget  int
	entries int
}

// requestSize estimates the memory a parked record keeps alive.
func requestSize(t *Transaction) int {
	size := 1024 + len(t.Request) + len(t.Response)
	for _, field := range []string{t.ID, t.Protocol, t.Backend, t.LocalEndpoint, t.Service, t.TargetID, t.Host, t.Source, t.Client, t.PeerClient, t.ClientSource, t.Connection, t.Method, t.URL} {
		size += len(field)
	}
	for _, reason := range t.IntegrityReasons {
		size += 32 + len(reason)
	}
	for _, trailers := range []map[string][]string{t.RequestTrailers, t.ResponseTrailers} {
		for key, values := range trailers {
			size += 128 + len(key)
			for _, value := range values {
				size += 32 + len(value)
			}
		}
	}
	return size
}

func (c *requestCache) limits() (int, int) {
	budget, entries := c.budget, c.entries
	if budget <= 0 {
		budget = requestCacheBudget
	}
	if entries <= 0 {
		entries = requestCacheEntries
	}
	return budget, entries
}

func (c *requestCache) remove(e *list.Element) Transaction {
	entry := e.Value.(requestCacheEntry)
	delete(c.items, entry.record.ID)
	c.bytes -= entry.size
	c.order.Remove(e)
	return entry.record
}

// park takes ownership of an unpaired request. spill persists a request that
// leaves the cache unpaired; park returns the first spill error.
func (c *requestCache) park(t Transaction, spill func(Transaction) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.items[t.ID]; e != nil {
		c.remove(e)
	}
	budget, entries := c.limits()
	size := requestSize(&t)
	if size > budget {
		return spill(t)
	}
	var first error
	for c.order.Len() > 0 && (c.bytes+size > budget || c.order.Len() >= entries) {
		if err := spill(c.remove(c.order.Front())); err != nil && first == nil {
			first = err
		}
	}
	if c.items == nil {
		c.items = make(map[string]*list.Element)
	}
	c.items[t.ID] = c.order.PushBack(requestCacheEntry{t, size})
	c.bytes += size
	return first
}

// take removes a parked request and returns it with ownership.
func (c *requestCache) take(id string) (Transaction, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.items[id]; e != nil {
		return c.remove(e), true
	}
	return Transaction{}, false
}

// parkPending keeps an unpaired request in memory until its response arrives
// or finish()/invalidate() persists it. Only eviction writes it earlier.
func (s *Store) parkPending(t Transaction) error {
	return s.requests.park(t, s.save)
}

// restorePending returns a parked request, or the copy an eviction spilled.
func (s *Store) restorePending(record *Transaction) error {
	if parked, ok := s.requests.take(record.ID); ok {
		*record = parked
		return nil
	}
	return s.restore(record)
}
