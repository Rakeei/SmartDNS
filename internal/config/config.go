package config

import (
	"fmt"
	"net"
	"os"
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

	PublicIP     string   `yaml:"public_ip"`
	PublicIPv6   string   `yaml:"public_ipv6"`
	UpstreamDNS  []string `yaml:"upstream_dns"`
	Domains      []string `yaml:"domains"`
	AllowedCIDRs []string `yaml:"allowed_cidrs"`

	publicIP   net.IP
	publicIPv6 net.IP
	allowed    []*net.IPNet
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
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
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
	if c.publicIP == nil || c.publicIP.To4() == nil {
		return fmt.Errorf("invalid public_ip (must be IPv4): %s", c.PublicIP)
	}

	if c.PublicIPv6 != "" {
		c.publicIPv6 = net.ParseIP(c.PublicIPv6)
		if c.publicIPv6 == nil || c.publicIPv6.To4() != nil {
			return fmt.Errorf("invalid public_ipv6 (must be IPv6): %s", c.PublicIPv6)
		}
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
		cidr := entry
		if !strings.Contains(cidr, "/") {
			if ip := net.ParseIP(entry); ip != nil && ip.To4() != nil {
				cidr = entry + "/32"
			} else {
				cidr = entry + "/128"
			}
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid allowed_cidrs entry %q: %w", entry, err)
		}
		c.allowed = append(c.allowed, n)
	}

	return nil
}

// PublicIPAddr returns the IPv4 handed out for smart-routed domains' A records.
func (c *Config) PublicIPAddr() net.IP { return c.publicIP }

// PublicIPv6Addr returns the IPv6 handed out for smart-routed domains' AAAA
// records, or nil if no public_ipv6 is configured.
func (c *Config) PublicIPv6Addr() net.IP { return c.publicIPv6 }

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
