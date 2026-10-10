package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrInvalidEntry marks input rejected by syntax validation, as opposed to
// I/O failures, so callers can tell a bad request from a server fault.
var ErrInvalidEntry = errors.New("invalid entry")

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

// NormalizeDomain lowercases and trims a domain and strips a trailing dot.
func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// AppendDomain normalizes, syntax-checks, and appends domain to the list
// file at path, skipping it if already present. It reports whether the
// domain was newly added.
func AppendDomain(path, domain string) (bool, error) {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return false, fmt.Errorf("%w: empty domain", ErrInvalidEntry)
	}
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		return false, fmt.Errorf("%w: domain syntax %q", ErrInvalidEntry, domain)
	}
	return appendUnique(path, domain)
}

// AppendCIDR validates entry as an IP or CIDR and appends it to the list
// file at path, skipping it if already present. It reports whether the
// entry was newly added.
func AppendCIDR(path, entry string) (bool, error) {
	entry = strings.TrimSpace(entry)
	if _, err := parseCIDR(entry); err != nil {
		return false, fmt.Errorf("%w: IP/CIDR %q", ErrInvalidEntry, entry)
	}
	return appendUnique(path, entry)
}

// RemoveEntry deletes every line exactly equal to value from the list file at
// path. It's used to roll back an add whose reload failed.
func RemoveEntry(path, value string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))
	changed := false
	for _, l := range lines {
		if strings.TrimSpace(l) == value {
			changed = true
			continue
		}
		out = append(out, l)
	}
	if !changed {
		return nil
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0644)
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

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// A hand-edited file may lack a final newline; without this guard the new
	// entry would be glued onto the last line and corrupt both entries.
	prefix := ""
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	if st.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, st.Size()-1); err != nil {
			return false, err
		}
		if last[0] != '\n' {
			prefix = "\n"
		}
	}
	if _, err := f.WriteString(prefix + value + "\n"); err != nil {
		return false, err
	}
	return true, nil
}
