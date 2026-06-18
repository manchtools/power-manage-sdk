package netconfig

import (
	"errors"
	"fmt"
	"net"
	"regexp"
)

// ErrInvalidConfig is returned when an InterfaceConfig field is unsafe or
// malformed. Apply validates before touching any backend, so a bad config is
// rejected without side effects.
var ErrInvalidConfig = errors.New("netconfig: invalid config")

// validInterface matches a Linux interface name: first char alphanumeric (so it
// is never flag-shaped), the kernel's permitted charset, IFNAMSIZ-1 (15) length.
var validInterface = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,14}$`)

// validateInterfaceName rejects an empty or malformed interface name.
func validateInterfaceName(name string) error {
	if !validInterface.MatchString(name) {
		return fmt.Errorf("%w: interface %q is not a valid interface name", ErrInvalidConfig, name)
	}
	return nil
}

// validateInterfaceConfig enforces that every field is safe for an nmcli argv or
// a root-owned .network file: a valid ifname, a chosen address mode, CIDR
// addresses, IP-literal gateway/DNS/route gateways, CIDR-or-"default" route
// destinations, and a sane MTU. All provided values are validated regardless of
// mode (a malformed value is always wrong); the backends emit only the fields
// relevant to the mode.
func validateInterfaceConfig(cfg InterfaceConfig) error {
	if err := validateInterfaceName(cfg.Name); err != nil {
		return err
	}
	if cfg.Mode != DHCP && cfg.Mode != Static {
		return fmt.Errorf("%w: address mode must be DHCP or Static (got %d)", ErrInvalidConfig, int(cfg.Mode))
	}
	if cfg.Mode == Static && len(cfg.Addresses) == 0 {
		return fmt.Errorf("%w: static mode requires at least one address", ErrInvalidConfig)
	}
	var hasV4, hasV6 bool
	for _, a := range cfg.Addresses {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			return fmt.Errorf("%w: address %q is not valid CIDR", ErrInvalidConfig, a)
		}
		if ip.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	if cfg.Gateway != "" {
		gwIP := net.ParseIP(cfg.Gateway)
		if gwIP == nil {
			return fmt.Errorf("%w: gateway %q is not a valid IP address", ErrInvalidConfig, cfg.Gateway)
		}
		// In static mode a gateway must share a family with a configured
		// address, otherwise it would be silently dropped (a v6 gateway with
		// only v4 addresses has nowhere to attach). Fail closed rather than
		// quietly ignore it. (DHCP ignores Gateway entirely, so skip the check.)
		if cfg.Mode == Static {
			if gwV4 := gwIP.To4() != nil; (gwV4 && !hasV4) || (!gwV4 && !hasV6) {
				return fmt.Errorf("%w: gateway %q family does not match any configured address", ErrInvalidConfig, cfg.Gateway)
			}
		}
	}
	for _, d := range cfg.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("%w: DNS %q is not a valid IP address", ErrInvalidConfig, d)
		}
	}
	if cfg.MTU != 0 && (cfg.MTU < 68 || cfg.MTU > 65535) {
		return fmt.Errorf("%w: MTU %d out of range (68..65535, or 0 for default)", ErrInvalidConfig, cfg.MTU)
	}
	for _, rt := range cfg.Routes {
		if err := validateRoute(rt); err != nil {
			return err
		}
	}
	return nil
}

// validateRoute checks a single route entry.
func validateRoute(rt Route) error {
	if rt.Destination != "default" {
		if _, _, err := net.ParseCIDR(rt.Destination); err != nil {
			return fmt.Errorf("%w: route destination %q must be CIDR or \"default\"", ErrInvalidConfig, rt.Destination)
		}
	}
	if net.ParseIP(rt.Gateway) == nil {
		return fmt.Errorf("%w: route to %q has invalid gateway %q", ErrInvalidConfig, rt.Destination, rt.Gateway)
	}
	if rt.Metric < 0 {
		return fmt.Errorf("%w: route to %q has negative metric %d", ErrInvalidConfig, rt.Destination, rt.Metric)
	}
	return nil
}

// partitionAddrsByFamily splits validated CIDR addresses into IPv4 and IPv6
// (NetworkManager and networkd set them on separate properties/keys).
func partitionAddrsByFamily(addrs []string) (v4, v6 []string) {
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			continue // unreachable post-validation
		}
		if ip.To4() != nil {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return v4, v6
}

// partitionIPsByFamily splits validated IP literals (DNS servers) into IPv4 and
// IPv6.
func partitionIPsByFamily(ips []string) (v4, v6 []string) {
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue // unreachable post-validation
		}
		if ip.To4() != nil {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	return v4, v6
}
