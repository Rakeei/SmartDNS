// Package resolver looks up the real A-record IP of a domain directly against
// upstream DNS servers, bypassing the smart-routing logic so that the proxy
// components know where to actually connect.
package resolver

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var ErrNoRecord = errors.New("resolver: no A record found")

// maxCacheEntries bounds the resolver cache so a flood of lookups for
// distinct hostnames (e.g. many subdomains of a smart-routed domain) can't
// grow it without limit.
const maxCacheEntries = 10000

// cacheSweepInterval controls how often expired entries are purged, so
// entries whose TTL passed are reclaimed even without a fresh lookup for
// the same domain.
const cacheSweepInterval = 5 * time.Minute

type cacheEntry struct {
	ip      string
	expires time.Time
}

type Resolver struct {
	upstream atomic.Pointer[[]string]
	client   *dns.Client

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

func New(upstream []string) *Resolver {
	r := &Resolver{
		client: &dns.Client{Timeout: 3 * time.Second},
		cache:  make(map[string]cacheEntry),
	}
	r.UpdateUpstream(upstream)
	go r.sweepLoop()
	return r
}

// sweepLoop periodically drops expired cache entries so memory used by
// stale lookups is reclaimed even for domains that are never queried again.
func (r *Resolver) sweepLoop() {
	ticker := time.NewTicker(cacheSweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		r.mu.Lock()
		for domain, e := range r.cache {
			if now.After(e.expires) {
				delete(r.cache, domain)
			}
		}
		r.mu.Unlock()
	}
}

// UpdateUpstream atomically swaps the list of upstream DNS servers used for
// future lookups. Cached answers are left in place.
func (r *Resolver) UpdateUpstream(upstream []string) {
	cp := append([]string(nil), upstream...)
	r.upstream.Store(&cp)
}

// ResolveA returns the real IPv4 address for domain, using a short-lived cache
// keyed by the upstream-reported TTL.
func (r *Resolver) ResolveA(domain string) (string, error) {
	if ip, ok := r.fromCache(domain); ok {
		return ip, nil
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	var lastErr error
	for _, up := range *r.upstream.Load() {
		resp, _, err := r.client.Exchange(m, up)
		if err != nil {
			lastErr = err
			continue
		}
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ttl := time.Duration(a.Hdr.Ttl) * time.Second
				if ttl < time.Second {
					ttl = time.Second
				}
				ip := a.A.String()
				r.toCache(domain, ip, ttl)
				return ip, nil
			}
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", ErrNoRecord
}

func (r *Resolver) fromCache(domain string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.cache[domain]
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.ip, true
}

func (r *Resolver) toCache(domain, ip string, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.cache[domain]; !exists && len(r.cache) >= maxCacheEntries {
		// Cache is full of still-live entries and this is a new domain:
		// drop the insert rather than growing past the cap. The next sweep
		// or a naturally expiring entry will free up room.
		return
	}
	r.cache[domain] = cacheEntry{ip: ip, expires: time.Now().Add(ttl)}
}
