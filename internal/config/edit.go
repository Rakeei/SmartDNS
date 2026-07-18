package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// domainPattern is a practical FQDN syntax check: dot-separated labels of
// alphanumerics/hyphens (no leading/trailing hyphen), ending in a
// letters-only TLD of at least 2 characters.
var domainPattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

// ListFiles returns the resolved paths of the domains and allowed_cidrs list
// files declared in the config at path. Unlike Load, it doesn't validate the
// rest of the config, so it works even when a list file is empty or missing
// (e.g. before the first `smartdns add-domain`).
func ListFiles(path string) (domainsFile, allowedCIDRsFile string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read config: %w", err)
	}
	var c struct {
		DomainsFile      string `yaml:"domains_file"`
		AllowedCIDRsFile string `yaml:"allowed_cidrs_file"`
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return "", "", fmt.Errorf("parse config: %w", err)
	}
	if c.DomainsFile == "" || c.AllowedCIDRsFile == "" {
		return "", "", fmt.Errorf("config must set domains_file and allowed_cidrs_file")
	}
	dir := filepath.Dir(path)
	return resolvePath(dir, c.DomainsFile), resolvePath(dir, c.AllowedCIDRsFile), nil
}

// ReadList returns the parsed entries (comments and blank lines skipped) of
// a domains or allowed_cidrs list file, e.g. for a `/list` command.
func ReadList(path string) ([]string, error) {
	return readLines(path)
}

// AppendDomain normalizes, syntax-checks, and appends domain to the list
// file at path, skipping it if already present. It reports whether the
// domain was newly added.
func AppendDomain(path, domain string) (bool, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return false, fmt.Errorf("empty domain")
	}
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		return false, fmt.Errorf("invalid domain syntax: %q", domain)
	}
	return appendUnique(path, domain)
}

// AppendCIDR validates entry as an IP or CIDR and appends it to the list
// file at path, skipping it if already present. It reports whether the
// entry was newly added.
func AppendCIDR(path, entry string) (bool, error) {
	entry = strings.TrimSpace(entry)
	if _, err := parseCIDR(entry); err != nil {
		return false, fmt.Errorf("invalid IP/CIDR %q: %w", entry, err)
	}
	return appendUnique(path, entry)
}

func appendUnique(path, value string) (bool, error) {
	existing, err := readLines(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	for _, e := range existing {
		if e == value {
			return false, nil
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if _, err := f.WriteString(value + "\n"); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveLine removes the first entry equal to value from the list file at
// path (comments and blank lines are left untouched), rewriting the file in
// place. It reports whether an entry was actually removed.
//
// The file is rewritten via os.WriteFile, which truncates and rewrites the
// existing file in place rather than renaming a new one over it — important
// because domains.txt/allowed_ips.txt are typically Docker single-file bind
// mounts, and a rename-based rewrite (as e.g. `sed -i` does) would silently
// swap the underlying inode out from under the mount.
func RemoveLine(path, value string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	var lines []string
	removed := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !removed && strings.TrimSpace(line) == value {
			removed = true
			continue
		}
		lines = append(lines, line)
	}
	scErr := sc.Err()
	f.Close()
	if scErr != nil {
		return false, scErr
	}
	if !removed {
		return false, nil
	}

	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	return true, os.WriteFile(path, []byte(content), 0644)
}
