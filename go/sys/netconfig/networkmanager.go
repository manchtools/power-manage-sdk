package netconfig

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// nmBackend configures an interface's active NetworkManager connection via nmcli.
type nmBackend struct {
	base
}

// Apply validates cfg, resolves the active connection on cfg.Name, applies the
// IP configuration to it, and reactivates it.
//
// MTU is set via 802-3-ethernet.mtu (ethernet-oriented); on a non-ethernet
// connection nmcli will reject it and the error surfaces — use the
// SystemdNetworkd backend for MTU on other link types. For each family, settings
// are applied only when that family has addresses (so a static-v4-only config
// leaves v6 at NetworkManager's default rather than forcing it off).
func (b *nmBackend) Apply(ctx context.Context, cfg InterfaceConfig) error {
	if err := validateInterfaceConfig(cfg); err != nil {
		return err
	}
	conn, err := b.activeConnection(ctx, cfg.Name)
	if err != nil {
		return err
	}
	args := append([]string{"connection", "modify", conn}, nmModifyArgs(cfg)...)
	if err := runPriv(ctx, b.r, "nmcli", args...); err != nil {
		return fmt.Errorf("nmcli connection modify %s: %w", conn, err)
	}
	if err := runPriv(ctx, b.r, "nmcli", "connection", "up", conn); err != nil {
		return fmt.Errorf("nmcli connection up %s: %w", conn, err)
	}
	return nil
}

// activeConnection resolves the connection name bound to iface.
func (b *nmBackend) activeConnection(ctx context.Context, iface string) (string, error) {
	out, err := runRead(ctx, b.r, "nmcli", "-g", "GENERAL.CONNECTION", "device", "show", iface)
	if err != nil {
		return "", fmt.Errorf("resolve connection for %s: %w", iface, err)
	}
	conn := strings.TrimSpace(out)
	if conn == "" || conn == "--" {
		return "", fmt.Errorf("%w: interface %q has no active NetworkManager connection to configure", ErrInvalidConfig, iface)
	}
	return conn, nil
}

// nmModifyArgs builds the `nmcli connection modify` property/value pairs for cfg.
func nmModifyArgs(cfg InterfaceConfig) []string {
	var a []string
	if cfg.Mode == DHCP {
		// Make DHCP authoritative: switch both families to auto and clear any
		// stale manual addressing.
		a = append(a,
			"ipv4.method", "auto", "ipv4.addresses", "", "ipv4.gateway", "",
			"ipv6.method", "auto", "ipv6.addresses", "", "ipv6.gateway", "",
		)
	} else {
		v4addr, v6addr := partitionAddrsByFamily(cfg.Addresses)
		gwV4, gwV6 := splitGatewayByFamily(cfg.Gateway)
		if len(v4addr) > 0 {
			a = append(a, "ipv4.method", "manual", "ipv4.addresses", strings.Join(v4addr, ","))
			if gwV4 != "" {
				a = append(a, "ipv4.gateway", gwV4)
			}
		}
		if len(v6addr) > 0 {
			a = append(a, "ipv6.method", "manual", "ipv6.addresses", strings.Join(v6addr, ","))
			if gwV6 != "" {
				a = append(a, "ipv6.gateway", gwV6)
			}
		}
	}
	if v4dns, v6dns := partitionIPsByFamily(cfg.DNS); len(v4dns) > 0 || len(v6dns) > 0 {
		if len(v4dns) > 0 {
			a = append(a, "ipv4.dns", strings.Join(v4dns, ","))
		}
		if len(v6dns) > 0 {
			a = append(a, "ipv6.dns", strings.Join(v6dns, ","))
		}
	}
	if cfg.MTU != 0 {
		a = append(a, "802-3-ethernet.mtu", strconv.Itoa(cfg.MTU))
	}
	if v4r, v6r := nmRoutesByFamily(cfg.Routes); len(v4r) > 0 || len(v6r) > 0 {
		if len(v4r) > 0 {
			a = append(a, "ipv4.routes", strings.Join(v4r, ","))
		}
		if len(v6r) > 0 {
			a = append(a, "ipv6.routes", strings.Join(v6r, ","))
		}
	}
	return a
}

// splitGatewayByFamily returns the gateway as (v4, v6) — exactly one is set (or
// neither when gw is empty). gw is a validated IP literal.
func splitGatewayByFamily(gw string) (v4, v6 string) {
	if gw == "" {
		return "", ""
	}
	if net.ParseIP(gw).To4() != nil {
		return gw, ""
	}
	return "", gw
}

// nmRoutesByFamily renders each route as nmcli's "<dest> <gateway> [metric]"
// form, bucketed by the gateway's family. A "default" destination becomes the
// family-appropriate default CIDR.
func nmRoutesByFamily(routes []Route) (v4, v6 []string) {
	for _, rt := range routes {
		isV4 := net.ParseIP(rt.Gateway).To4() != nil
		dst := rt.Destination
		if dst == "default" {
			if isV4 {
				dst = "0.0.0.0/0"
			} else {
				dst = "::/0"
			}
		}
		s := dst + " " + rt.Gateway
		if rt.Metric != 0 {
			s += " " + strconv.Itoa(rt.Metric)
		}
		if isV4 {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	return v4, v6
}
