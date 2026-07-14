// Command smartdns is a smart-DNS + HTTP/HTTPS passthrough proxy: it answers
// DNS queries for configured domains with this server's own IP, and then
// proxies the resulting HTTP/HTTPS traffic through to the real origin.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"smartdns/internal/config"
	"smartdns/internal/dnsserver"
	"smartdns/internal/httpproxy"
	"smartdns/internal/resolver"
	"smartdns/internal/sniproxy"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store := config.NewStore(cfg)
	res := resolver.New(cfg.UpstreamDNS)

	go watchReload(*cfgPath, store, res)

	errCh := make(chan error, 3)

	dnsSrv := dnsserver.New(store)
	go func() {
		log.Printf("dns: listening on %s (udp+tcp)", cfg.Listen.DNS)
		errCh <- dnsSrv.ListenAndServe(cfg.Listen.DNS)
	}()

	httpSrv := httpproxy.New(store, res)
	go func() {
		log.Printf("http proxy: listening on %s", cfg.Listen.HTTP)
		errCh <- httpSrv.ListenAndServe(cfg.Listen.HTTP)
	}()

	sniSrv := sniproxy.New(store, res)
	go func() {
		log.Printf("sni proxy: listening on %s", cfg.Listen.HTTPS)
		errCh <- sniSrv.ListenAndServe(cfg.Listen.HTTPS)
	}()

	log.Fatal(<-errCh)
}

// watchReload reloads the config file every time the process receives
// SIGHUP, swapping it into store atomically. Listener ports (dns/http/https)
// are read once at startup and are not affected by reload; everything else
// (domains, allowed_cidrs, public_ip, upstream_dns) takes effect immediately
// for new connections. A reload that fails validation is logged and ignored,
// leaving the previously running config untouched.
func watchReload(cfgPath string, store *config.Store, res *resolver.Resolver) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	for range sigCh {
		newCfg, err := config.Load(cfgPath)
		if err != nil {
			log.Printf("reload: keeping previous config, failed to load %s: %v", cfgPath, err)
			continue
		}
		store.Set(newCfg)
		res.UpdateUpstream(newCfg.UpstreamDNS)
		log.Printf("reload: applied config from %s (%d domains, %d allowed CIDRs)",
			cfgPath, len(newCfg.Domains), len(newCfg.AllowedCIDRs))
	}
}
