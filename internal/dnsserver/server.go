// Package dnsserver implements the smart-DNS resolver: domains on the smart
// list get this server's own public IP back, everything else is forwarded
// verbatim to the configured upstream DNS servers.
package dnsserver

import (
	"log"
	"net"
	"time"

	"github.com/miekg/dns"

	"smartdns/internal/config"
)

type Server struct {
	store *config.Store
}

func New(store *config.Store) *Server {
	return &Server{store: store}
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
		if (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) && cfg.MatchesDomain(q.Name) {
			log.Printf("dns: query client=%s name=%s type=%s -> smart-routed to %s",
				client, q.Name, dns.TypeToString[q.Qtype], cfg.PublicIPAddr())
			s.answerSmart(cfg, w, r, q)
			return
		}
		log.Printf("dns: query client=%s name=%s type=%s -> forwarded upstream",
			client, q.Name, dns.TypeToString[q.Qtype])
	}

	s.forward(cfg, w, r)
}

// answerSmart replies with this server's own public IP so that subsequent
// HTTP/HTTPS traffic for the domain lands on our proxy.
func (s *Server) answerSmart(cfg *config.Config, w dns.ResponseWriter, r *dns.Msg, q dns.Question) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	ip := cfg.PublicIPAddr()
	switch {
	case q.Qtype == dns.TypeA && ip.To4() != nil:
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip.To4(),
		})
	case q.Qtype == dns.TypeAAAA && ip.To4() == nil && ip.To16() != nil:
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: ip.To16(),
		})
	}
	// If the query type doesn't match the family of public_ip, we reply with
	// an empty NOERROR answer rather than forwarding, so the real IP of a
	// smart-routed domain is never leaked over the mismatched record type.

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("dns: write response: %v", err)
	}
}

// forward relays the query untouched to the upstream DNS servers and returns
// whatever answer comes back first.
func (s *Server) forward(cfg *config.Config, w dns.ResponseWriter, r *dns.Msg) {
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
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("dns: write forwarded response: %v", err)
	}
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
