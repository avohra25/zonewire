package server

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/avohra25/zonewire/dns"
)

type cacheKey struct {
	name string
	t    dns.Type
}

type cacheEntry struct {
	key     cacheKey
	msg     *dns.Message
	stored  time.Time
	expires time.Time
}

// Cache stores replies for as long as their TTLs allow, with negative
// answers kept for the SOA minimum (RFC 2308) and LRU eviction.
type Cache struct {
	// Now is the clock; tests replace it.
	Now func() time.Time
	// MaxEntries bounds the cache (default 10000).
	MaxEntries int
	// MaxTTL caps how long any answer is kept (default 1 day).
	MaxTTL time.Duration

	mu      sync.Mutex
	entries map[cacheKey]*list.Element
	lru     *list.List

	Hits, Misses int
}

// NewCache returns an empty cache using the real clock.
func NewCache() *Cache {
	return &Cache{Now: time.Now, entries: map[cacheKey]*list.Element{}, lru: list.New()}
}

func keyOf(name string, t dns.Type) cacheKey {
	if n, err := dns.CanonicalName(name); err == nil {
		name = n
	}
	return cacheKey{strings.ToLower(name), t}
}

// ttlOf returns how long a reply may be cached, and false if it must not be.
func (c *Cache) ttlOf(m *dns.Message) (time.Duration, bool) {
	if m.Truncated || (m.RCode != dns.RCodeSuccess && m.RCode != dns.RCodeNameError) {
		return 0, false
	}
	var min uint32
	found := false
	consider := func(ttl uint32) {
		if !found || ttl < min {
			min, found = ttl, true
		}
	}
	if len(m.Answers) > 0 {
		for _, rr := range m.Answers {
			consider(rr.TTL)
		}
	} else {
		// Negative answer: lifetime comes from the SOA in authority.
		for _, rr := range m.Authority {
			if soa, ok := rr.Data.(dns.SOA); ok {
				consider(rr.TTL)
				consider(soa.MinTTL)
			}
		}
		if !found {
			return 0, false // no SOA, no negative caching
		}
	}
	d := time.Duration(min) * time.Second
	maxTTL := c.MaxTTL
	if maxTTL == 0 {
		maxTTL = 24 * time.Hour
	}
	if d > maxTTL {
		d = maxTTL
	}
	return d, d > 0
}

// Put stores a reply under its question.
func (c *Cache) Put(m *dns.Message) {
	if len(m.Questions) != 1 {
		return
	}
	ttl, ok := c.ttlOf(m)
	if !ok {
		return
	}
	now := c.Now()
	k := keyOf(m.Questions[0].Name, m.Questions[0].Type)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[k]; ok {
		c.lru.Remove(el)
	}
	c.entries[k] = c.lru.PushFront(&cacheEntry{k, m, now, now.Add(ttl)})
	max := c.MaxEntries
	if max == 0 {
		max = 10000
	}
	for c.lru.Len() > max {
		old := c.lru.Back()
		c.lru.Remove(old)
		delete(c.entries, old.Value.(*cacheEntry).key)
	}
}

// Get returns a cached reply with TTLs reduced by the time spent in the
// cache, or nil if there is none.
func (c *Cache) Get(name string, t dns.Type) *dns.Message {
	k := keyOf(name, t)
	now := c.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[k]
	if !ok {
		c.Misses++
		return nil
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.expires) {
		c.lru.Remove(el)
		delete(c.entries, k)
		c.Misses++
		return nil
	}
	c.lru.MoveToFront(el)
	c.Hits++
	age := uint32(now.Sub(e.stored) / time.Second)
	m := *e.msg
	m.Answers = aged(e.msg.Answers, age)
	m.Authority = aged(e.msg.Authority, age)
	m.Additional = aged(e.msg.Additional, age)
	return &m
}

func aged(rrs []dns.RR, age uint32) []dns.RR {
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		if rr.Type() != dns.TypeOPT {
			if rr.TTL > age {
				rr.TTL -= age
			} else {
				rr.TTL = 0
			}
		}
		out[i] = rr
	}
	return out
}

// Len reports how many replies are cached, including expired ones not yet
// evicted.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// CachingClient wraps a Client with a Cache.
type CachingClient struct {
	Client *Client
	Cache  *Cache
	Server string
}

// Query answers from the cache when possible and otherwise asks the server.
func (cc *CachingClient) Query(ctx context.Context, name string, t dns.Type) (*dns.Message, error) {
	if m := cc.Cache.Get(name, t); m != nil {
		return m, nil
	}
	m, err := cc.Client.Query(ctx, cc.Server, name, t)
	if err != nil {
		return nil, err
	}
	cc.Cache.Put(m)
	return m, nil
}
