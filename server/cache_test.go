package server

import (
	"context"
	"testing"
	"time"

	"github.com/avohra25/zonewire/dns"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func newTestCache() (*Cache, *fakeClock) {
	clk := &fakeClock{time.Unix(1_800_000_000, 0)}
	c := NewCache()
	c.Now = clk.now
	return c, clk
}

func TestCacheAgesTTLs(t *testing.T) {
	_, addr := startServer(t, testZone(t))
	cache, clk := newTestCache()
	cc := &CachingClient{Client: &Client{}, Cache: cache, Server: addr}
	ctx := context.Background()
	first, err := cc.Query(ctx, "www.example.com", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(100 * time.Second)
	second, err := cc.Query(ctx, "WWW.example.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if cache.Hits != 1 || cache.Misses != 1 {
		t.Fatalf("hits=%d misses=%d", cache.Hits, cache.Misses)
	}
	if first.Answers[0].TTL != 300 || second.Answers[0].TTL != 200 {
		t.Fatalf("TTLs %d then %d", first.Answers[0].TTL, second.Answers[0].TTL)
	}
	clk.advance(200 * time.Second)
	if cache.Get("www.example.com.", dns.TypeA) != nil {
		t.Fatal("entry should have expired")
	}
}

func TestNegativeCaching(t *testing.T) {
	_, addr := startServer(t, testZone(t))
	cache, clk := newTestCache()
	cc := &CachingClient{Client: &Client{}, Cache: cache, Server: addr}
	if _, err := cc.Query(context.Background(), "nope.example.com.", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	clk.advance(59 * time.Second)
	if m := cache.Get("nope.example.com.", dns.TypeA); m == nil || m.RCode != dns.RCodeNameError {
		t.Fatal("NXDOMAIN should be cached for the SOA minimum")
	}
	clk.advance(time.Second)
	if cache.Get("nope.example.com.", dns.TypeA) != nil {
		t.Fatal("negative entry outlived the SOA minimum")
	}
}

func TestCacheSkipsUncacheable(t *testing.T) {
	cache, _ := newTestCache()
	q, _ := dns.NewQuery(1, "x.", dns.TypeA)
	for _, mut := range []func(*dns.Message){
		func(m *dns.Message) { m.RCode = dns.RCodeServerFailure },
		func(m *dns.Message) { m.Truncated = true },
		func(m *dns.Message) {}, // NODATA without SOA
	} {
		r := q.Reply()
		mut(r)
		cache.Put(r)
	}
	if cache.Len() != 0 {
		t.Fatalf("cached %d uncacheable replies", cache.Len())
	}
}

func TestCacheLRUEviction(t *testing.T) {
	cache, _ := newTestCache()
	cache.MaxEntries = 2
	put := func(name string) {
		q, _ := dns.NewQuery(1, name, dns.TypeA)
		r := q.Reply()
		r.Answers = []dns.RR{{Name: q.Questions[0].Name, Class: dns.ClassINET, TTL: 60, Data: dns.CNAME{Target: "t."}}}
		cache.Put(r)
	}
	put("a.")
	put("b.")
	cache.Get("a.", dns.TypeA) // a is now most recently used
	put("c.")
	if cache.Get("b.", dns.TypeA) != nil || cache.Get("a.", dns.TypeA) == nil || cache.Get("c.", dns.TypeA) == nil {
		t.Fatal("expected b to be evicted")
	}
}

func TestCacheMaxTTL(t *testing.T) {
	cache, clk := newTestCache()
	cache.MaxTTL = time.Minute
	q, _ := dns.NewQuery(1, "long.", dns.TypeA)
	r := q.Reply()
	r.Answers = []dns.RR{{Name: "long.", Class: dns.ClassINET, TTL: 86400, Data: dns.CNAME{Target: "t."}}}
	cache.Put(r)
	clk.advance(61 * time.Second)
	if cache.Get("long.", dns.TypeA) != nil {
		t.Fatal("MaxTTL not enforced")
	}
}
