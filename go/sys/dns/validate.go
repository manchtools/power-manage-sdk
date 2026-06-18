package dns

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ErrInvalidConfig is returned when a Config field is unsafe or malformed for a
// resolver backend. Apply validates before touching any backend, so a bad config
// is rejected without side effects.
var ErrInvalidConfig = errors.New("dns: invalid config")

// validInterface matches a Linux interface name: first char alphanumeric (so it
// can never be flag-shaped), the kernel's permitted charset, and IFNAMSIZ-1 (15)
// length cap.
var validInterface = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,14}$`)

// validDomainLabel matches a single DNS label: alphanumeric ends, hyphens
// allowed interior, 1..63 chars.
var validDomainLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validateConfig enforces that every Config field is safe to place on a
// resolvectl/nmcli argv or into a root-owned resolved.conf.d drop-in:
//   - each nameserver parses as a literal IP (no hostnames, no flag shapes, no
//     shell/whitespace junk);
//   - each search domain is a valid, control-character-free DNS name with a
//     leading-alphanumeric first label (so it is never flag-shaped);
//   - the interface, if set, is a valid ifname.
func validateConfig(cfg Config) error {
	for _, ns := range cfg.Nameservers {
		if net.ParseIP(ns) == nil {
			return fmt.Errorf("%w: nameserver %q is not a valid IP address", ErrInvalidConfig, ns)
		}
	}
	for _, d := range cfg.SearchDomains {
		if err := validateDomain(d); err != nil {
			return err
		}
	}
	if cfg.Interface != "" && !validInterface.MatchString(cfg.Interface) {
		return fmt.Errorf("%w: interface %q is not a valid interface name", ErrInvalidConfig, cfg.Interface)
	}
	return nil
}

// validateDomain checks a single search-domain entry.
func validateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("%w: empty search domain", ErrInvalidConfig)
	}
	if len(d) > 253 {
		return fmt.Errorf("%w: search domain %q exceeds 253 characters", ErrInvalidConfig, d)
	}
	if strings.ContainsAny(d, " \t\n\r\x00") {
		return fmt.Errorf("%w: search domain %q contains whitespace or control characters", ErrInvalidConfig, d)
	}
	// A trailing dot (FQDN root) is permitted; strip it before label checks.
	labels := strings.Split(strings.TrimSuffix(d, "."), ".")
	for _, l := range labels {
		if !validDomainLabel.MatchString(l) {
			return fmt.Errorf("%w: search domain %q has an invalid label %q", ErrInvalidConfig, d, l)
		}
	}
	return nil
}

// partitionByFamily splits validated nameserver IPs into IPv4 and IPv6 buckets
// (NetworkManager sets them on ipv4.dns vs ipv6.dns separately). Inputs are
// already validated as IP literals by validateConfig.
func partitionByFamily(nameservers []string) (v4, v6 []string) {
	for _, ns := range nameservers {
		ip := net.ParseIP(ns)
		if ip == nil {
			continue // unreachable post-validation; skip defensively
		}
		if ip.To4() != nil {
			v4 = append(v4, ns)
		} else {
			v6 = append(v6, ns)
		}
	}
	return v4, v6
}
