package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"smartdns/internal/config"
)

// cmdAddDomain implements `smartdns add-domain [-config path] <domain>`.
func cmdAddDomain(args []string) {
	fs := flag.NewFlagSet("add-domain", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "path to config file")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: smartdns add-domain [-config path] <domain>")
	}
	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	domainsFile, _, err := config.ListFiles(*cfgPath)
	if err != nil {
		fatal("add-domain: %v", err)
	}

	added, err := config.AppendDomain(domainsFile, fs.Arg(0))
	if err != nil {
		fatal("add-domain: %v", err)
	}
	if !added {
		fmt.Printf("domain already present, nothing to do: %s\n", fs.Arg(0))
		return
	}

	fmt.Printf("added domain to %s: %s\n", domainsFile, fs.Arg(0))
	reportReload()
}

// cmdAddIP implements `smartdns add-ip [-config path] <ip-or-cidr>`.
func cmdAddIP(args []string) {
	fs := flag.NewFlagSet("add-ip", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "path to config file")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: smartdns add-ip [-config path] <ip-or-cidr>")
	}
	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	_, cidrsFile, err := config.ListFiles(*cfgPath)
	if err != nil {
		fatal("add-ip: %v", err)
	}

	added, err := config.AppendCIDR(cidrsFile, fs.Arg(0))
	if err != nil {
		fatal("add-ip: %v", err)
	}
	if !added {
		fmt.Printf("IP/CIDR already present, nothing to do: %s\n", fs.Arg(0))
		return
	}

	fmt.Printf("added IP/CIDR to %s: %s\n", cidrsFile, fs.Arg(0))
	reportReload()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// reportReload signals any running smartdns server (found by scanning
// /proc) to reload its config via SIGHUP, matching the reload behavior in
// watchReload, and prints whether it succeeded.
func reportReload() {
	if signalRunningServer() {
		fmt.Println("reloaded running smartdns server")
		return
	}
	fmt.Println("no running smartdns server found; changes take effect on next start or SIGHUP")
}

func signalRunningServer() bool {
	self := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	signaled := false
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			continue
		}
		fields := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		if len(fields) == 0 || !strings.Contains(fields[0], "smartdns") {
			continue
		}
		if isSubcommandInvocation(fields[1:]) {
			continue
		}
		if syscall.Kill(pid, syscall.SIGHUP) == nil {
			signaled = true
		}
	}
	return signaled
}

func isSubcommandInvocation(args []string) bool {
	for _, a := range args {
		if a == "add-domain" || a == "add-ip" {
			return true
		}
	}
	return false
}
