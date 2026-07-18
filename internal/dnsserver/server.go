// Package dnsserver implements the smart-DNS resolver: domains on the smart
// list get this server's own public IP back for every query type (so no
// record type can leak the real origin around the proxy), everything else is
// forwarded verbatim to the configured upstream DNS servers, with a bounded,
// TTL-respecting cache for the forwarded path.
package dnsserver

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"smartdns/internal/config"
)

// maxCacheEntries bounds the forward-response cache so a flood of lookups
// for distinct names can't grow it without limit.
const maxCacheEntries = 10000

// cacheSweepInterval controls how often expired entries are purged, so
// entries whose TTL passed are reclaimed even without a fresh lookup for
// the same name.
const cacheSweepInterval = 5 * time.Minute

type cacheEntry struct {
	msg      *dns.Msg
	cachedAt time.Time
	ttl      time.Duration
}

type Server struct {
	store *config.Store

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

func New(store *config.Store) *Server {
	s := &Server{store: store, cache: make(map[string]cacheEntry)}
	go s.sweepLoop()
	return s
}

func (s *Server) sweepLoop() {
	ticker := time.NewTicker(cacheSweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for key, e := range s.cache {
			if now.After(e.cachedAt.Add(e.ttl)) {
				delete(s.cache, key)
			}
		}
		s.mu.Unlock()
	}
}

// ListenAndServe starts both UDP and TCP DNS listeners on addr and blocks
// until one of them fails.
func (s *Server) ListenAndServe(addr string) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)

	errCh := make(chan error, 2)
	go func() {
		errCh <- (&dns.Server{Addr: addr, Net: "udp", Handler: mux}).ListenAndServe()
	}()
	go func() {
		errCh <- (&dns.Server{Addr: addr, Net: "tcp", Handler: mux}).ListenAndServe()
	}()
	return <-errCh
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	cfg := s.store.Get()
	client := remoteIP(w.RemoteAddr())

	if !cfg.IsAllowed(client) {
		log.Printf("dns: query client=%s DENIED (not in allowed_cidrs)", client)
		dns.HandleFailed(w, r)
		return
	}

	if len(r.Question) == 1 {
		q := r.Question[0]
		if cfg.MatchesDomain(q.Name) {
			// Every query type for a smart-routed domain is answered here,
			// not just A/AAAA: forwarding e.g. an HTTPS/SVCB query upstream
			// would hand the client the real origin's IP hints directly,
			// letting it bypass this proxy entirely (e.g. via HTTP/3/QUIC).
			log.Printf("dns: query client=%s name=%s type=%s -> smart-routed",
				client, q.Name, dns.TypeToString[q.Qtype])
			s.answerSmart(cfg, w, r, q)
			return
		}
		log.Printf("dns: query client=%s name=%s type=%s -> forwarded upstream",
			client, q.Name, dns.TypeToString[q.Qtype])
	}

	s.forward(cfg, w, r)
}

// answerSmart replies with this server's own public IP so that subsequent
// HTTP/HTTPS traffic for the domain lands on our proxy. Only A and AAAA get
// a real answer (AAAA only if public_ipv6 is configured); every other query
// type gets an empty NOERROR response rather than being forwarded, so no
// record type can leak the real origin around the proxy.
func (s *Server) answerSmart(cfg *config.Config, w dns.ResponseWriter, r *dns.Msg, q dns.Question) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	switch q.Qtype {
	case dns.TypeA:
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   cfg.PublicIPAddr().To4(),
		})
	case dns.TypeAAAA:
		if ip6 := cfg.PublicIPv6Addr(); ip6 != nil {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: ip6,
			})
		}
		// No public_ipv6 configured: empty NOERROR, forcing the client back
		// onto A instead of leaking anything via forwarding.
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("dns: write response: %v", err)
	}
}

// forward relays the query to the upstream DNS servers, serving from a
// short-lived cache (bounded by maxCacheEntries, keyed by TTL) when
// possible so repeat lookups for popular non-smart domains don't all round
// -trip to upstream.
func (s *Server) forward(cfg *config.Config, w dns.ResponseWriter, r *dns.Msg) {
	cacheable := len(r.Question) == 1
	var key string
	if cacheable {
		key = cacheKey(r.Question[0])
		if cached, ok := s.fromCache(key); ok {
			cached.SetReply(r)
			if err := w.WriteMsg(cached); err != nil {
				log.Printf("dns: write cached response: %v", err)
			}
			return
		}
	}

	network := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		network = "tcp"
	}
	c := &dns.Client{Net: network, Timeout: 3 * time.Second}

	var resp *dns.Msg
	var err error
	for _, up := range cfg.UpstreamDNS {
		resp, _, err = c.Exchange(r, up)
		if err == nil && resp != nil {
			break
		}
	}
	if err != nil || resp == nil {
		dns.HandleFailed(w, r)
		return
	}

	if cacheable && resp.Rcode == dns.RcodeSuccess {
		s.toCache(key, resp)
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("dns: write forwarded response: %v", err)
	}
}

func cacheKey(q dns.Question) string {
	return fmt.Sprintf("%d:%s", q.Qtype, strings.ToLower(q.Name))
}

// fromCache returns a copy of the cached message with TTLs adjusted for
// elapsed time, or ok=false if there's no live entry.
func (s *Server) fromCache(key string) (*dns.Msg, bool) {
	s.mu.RLock()
	e, ok := s.cache[key]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}

	elapsed := time.Since(e.cachedAt)
	if elapsed >= e.ttl {
		return nil, false
	}

	msg := e.msg.Copy()
	elapsedSec := uint32(elapsed / time.Second)
	for _, rr := range msg.Answer {
		hdr := rr.Header()
		if hdr.Ttl > elapsedSec {
			hdr.Ttl -= elapsedSec
		} else {
			hdr.Ttl = 0
		}
	}
	return msg, true
}

func (s *Server) toCache(key string, resp *dns.Msg) {
	ttl := minTTL(resp.Answer)
	if ttl <= 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.cache[key]; !exists && len(s.cache) >= maxCacheEntries {
		// Cache is full of still-live entries and this is a new name: drop
		// the insert rather than growing past the cap. The next sweep or a
		// naturally expiring entry will free up room.
		return
	}
	s.cache[key] = cacheEntry{msg: resp.Copy(), cachedAt: time.Now(), ttl: time.Duration(ttl) * time.Second}
}

func minTTL(rrs []dns.RR) uint32 {
	if len(rrs) == 0 {
		return 0
	}
	min := rrs[0].Header().Ttl
	for _, rr := range rrs[1:] {
		if t := rr.Header().Ttl; t < min {
			min = t
		}
	}
	return min
}

func remoteIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	default:
		return nil
	}
}
