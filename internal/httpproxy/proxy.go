// Package httpproxy forwards plain HTTP traffic (port 80) for smart-routed
// domains to the real origin server, resolved via the upstream DNS servers.
package httpproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"smartdns/internal/config"
	"smartdns/internal/resolver"
)

type Proxy struct {
	store *config.Store
	res   *resolver.Resolver
}

func New(store *config.Store, res *resolver.Resolver) *Proxy {
	return &Proxy{store: store, res: res}
}

func (p *Proxy) ListenAndServe(addr string) error {
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = req.Host
		},
		Transport: &http.Transport{
			DialContext:           p.dial,
			ResponseHeaderTimeout: 15 * time.Second,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cfg := p.store.Get()
		host := hostOnly(r.Host)
		if host == "" || !cfg.MatchesDomain(host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !cfg.IsAllowed(clientIP(r.RemoteAddr)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		rp.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	return srv.ListenAndServe()
}

// dial resolves the real origin IP for the requested hostname via upstream
// DNS (never via our own smart-routing) and connects to that instead.
func (p *Proxy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "80"
	}
	ip, err := p.res.ResolveA(host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

func clientIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return net.ParseIP(remoteAddr)
	}
	return net.ParseIP(host)
}
