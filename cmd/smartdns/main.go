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
	"smartdns/internal/telegrambot"
)

func main() {
	switch args := os.Args; {
	case len(args) > 1 && args[1] == "add-domain":
		cmdAddDomain(args[2:])
		return
	case len(args) > 1 && args[1] == "add-ip":
		cmdAddIP(args[2:])
		return
	}

	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store := config.NewStore(cfg)
	res := resolver.New(cfg.UpstreamDNS)

	go watchReload(*cfgPath, store, res)

	if cfg.TelegramBot.Token != "" {
		startTelegramBot(*cfgPath, cfg, store, res)
	}

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
		newCfg, err := reloadConfig(cfgPath, store, res)
		if err != nil {
			log.Printf("reload: keeping previous config, failed to load %s: %v", cfgPath, err)
			continue
		}
		log.Printf("reload: applied config from %s (%d domains, %d allowed CIDRs)",
			cfgPath, len(newCfg.Domains), len(newCfg.AllowedCIDRs))
	}
}

// reloadConfig re-reads cfgPath and, if it validates, swaps it into store
// and updates res's upstream DNS servers. Shared by the SIGHUP handler above
// and the Telegram bot's add-domain/add-ip commands.
func reloadConfig(cfgPath string, store *config.Store, res *resolver.Resolver) (*config.Config, error) {
	newCfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	store.Set(newCfg)
	res.UpdateUpstream(newCfg.UpstreamDNS)
	return newCfg, nil
}

// startTelegramBot wires up the optional Telegram admin bot: it lets
// allowlisted admin user IDs add domains/IPs to the live config via
// /add_domain and /add_ip. Disabled (with a log line explaining why) if the
// config doesn't declare domains_file/allowed_cidrs_file, since there'd be
// nowhere to persist the addition.
func startTelegramBot(cfgPath string, cfg *config.Config, store *config.Store, res *resolver.Resolver) {
	domainsFile, cidrsFile, err := config.ListFiles(cfgPath)
	if err != nil {
		log.Printf("telegram bot: disabled: %v", err)
		return
	}

	bot := telegrambot.New(cfg.TelegramBot.Token, cfg.TelegramBot.AdminIDs, domainsFile, cidrsFile,
		func() error {
			_, err := reloadConfig(cfgPath, store, res)
			return err
		})

	go func() {
		log.Printf("telegram bot: listening for admin commands (%d admins)", len(cfg.TelegramBot.AdminIDs))
		bot.Run()
	}()
}
