package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the full runtime configuration for smartdns, loaded from a YAML file.
type Config struct {
	Listen struct {
		DNS   string `yaml:"dns"`
		HTTP  string `yaml:"http"`
		HTTPS string `yaml:"https"`
	} `yaml:"listen"`

	PublicIP    string   `yaml:"public_ip"`
	UpstreamDNS []string `yaml:"upstream_dns"`

	// Domains and AllowedCIDRs are the effective, loaded lists. They can be
	// set inline in the YAML for backwards compatibility, but normally come
	// from DomainsFile / AllowedCIDRsFile so they can be edited (e.g. via
	// `smartdns add-domain` / `smartdns add-ip`) without touching the rest
	// of the config.
	Domains      []string `yaml:"domains"`
	AllowedCIDRs []string `yaml:"allowed_cidrs"`

	DomainsFile      string `yaml:"domains_file"`
	AllowedCIDRsFile string `yaml:"allowed_cidrs_file"`

	// TelegramBot optionally lets allowlisted Telegram admins add
	// domains/IPs remotely. Leave Token empty to disable it.
	TelegramBot struct {
		Token    string  `yaml:"token"`
		AdminIDs []int64 `yaml:"admin_ids"`
	} `yaml:"telegram_bot"`

	publicIP net.IP
	allowed  []*net.IPNet
}

// Load reads and validates a config file from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	dir := filepath.Dir(path)
	if c.DomainsFile != "" {
		lines, err := readLines(resolvePath(dir, c.DomainsFile))
		if err != nil {
			return nil, fmt.Errorf("read domains_file: %w", err)
		}
		c.Domains = append(c.Domains, lines...)
	}
	if c.AllowedCIDRsFile != "" {
		lines, err := readLines(resolvePath(dir, c.AllowedCIDRsFile))
		if err != nil {
			return nil, fmt.Errorf("read allowed_cidrs_file: %w", err)
		}
		c.AllowedCIDRs = append(c.AllowedCIDRs, lines...)
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// resolvePath resolves a config-referenced file path relative to the
// directory the config file itself lives in, so config.yaml stays portable
// regardless of the process's working directory.
func resolvePath(configDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(configDir, path)
}

// readLines reads a plain-text list file: one entry per line, blank lines
// and lines starting with "#" are ignored.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

func (c *Config) validate() error {
	if c.Listen.DNS == "" {
		c.Listen.DNS = ":53"
	}
	if c.Listen.HTTP == "" {
		c.Listen.HTTP = ":80"
	}
	if c.Listen.HTTPS == "" {
		c.Listen.HTTPS = ":443"
	}

	if c.PublicIP == "" {
		return fmt.Errorf("public_ip is required")
	}
	c.publicIP = net.ParseIP(c.PublicIP)
	if c.publicIP == nil {
		return fmt.Errorf("invalid public_ip: %s", c.PublicIP)
	}

	if len(c.UpstreamDNS) == 0 {
		c.UpstreamDNS = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	for i, u := range c.UpstreamDNS {
		if _, _, err := net.SplitHostPort(u); err != nil {
			c.UpstreamDNS[i] = net.JoinHostPort(u, "53")
		}
	}

	if len(c.Domains) == 0 {
		return fmt.Errorf("domains list is empty")
	}
	for i, d := range c.Domains {
		c.Domains[i] = strings.ToLower(strings.TrimSuffix(d, "."))
	}

	for _, entry := range c.AllowedCIDRs {
		n, err := parseCIDR(entry)
		if err != nil {
			return fmt.Errorf("invalid allowed_cidrs entry %q: %w", entry, err)
		}
		c.allowed = append(c.allowed, n)
	}

	return nil
}

func parseCIDR(entry string) (*net.IPNet, error) {
	cidr := entry
	if !strings.Contains(cidr, "/") {
		if ip := net.ParseIP(entry); ip != nil && ip.To4() != nil {
			cidr = entry + "/32"
		} else {
			cidr = entry + "/128"
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	return n, err
}

// PublicIPAddr returns the IP handed out for smart-routed domains.
func (c *Config) PublicIPAddr() net.IP { return c.publicIP }

// MatchesDomain reports whether qname (or one of its parent zones) is in the smart-routed domain list.
func (c *Config) MatchesDomain(qname string) bool {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, d := range c.Domains {
		if qname == d || strings.HasSuffix(qname, "."+d) {
			return true
		}
	}
	return false
}

// IsAllowed reports whether ip may use this service. An empty allowlist means everyone is allowed.
func (c *Config) IsAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if len(c.allowed) == 0 {
		return true
	}
	for _, n := range c.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
