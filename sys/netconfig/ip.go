package netconfig

import (
	"context"
	"encoding/json"
	"fmt"
)

// ipLink is the subset of `ip -j addr show` JSON we consume.
type ipLink struct {
	Ifname   string   `json:"ifname"`
	MTU      int      `json:"mtu"`
	AddrInfo []ipAddr `json:"addr_info"`
}

type ipAddr struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Prefixlen int    `json:"prefixlen"`
	Scope     string `json:"scope"`
}

// ipRoute is the subset of `ip -j route show` JSON we consume.
type ipRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Metric  int    `json:"metric"`
}

// Get reads the effective kernel state of name via `ip -j` (backend-agnostic:
// the kernel reflects whatever configured it). Addresses, MTU, Gateway, and
// Routes are populated; Mode and DNS are not recoverable from the kernel and are
// left zero. The interface name is validated to keep it off the argv as a flag.
func (b base) Get(ctx context.Context, name string) (InterfaceConfig, error) {
	if err := validateInterfaceName(name); err != nil {
		return InterfaceConfig{}, err
	}
	addrOut, err := runRead(ctx, b.r, "ip", "-j", "addr", "show", "dev", name)
	if err != nil {
		return InterfaceConfig{}, fmt.Errorf("ip addr show %s: %w", name, err)
	}
	routeOut, err := runRead(ctx, b.r, "ip", "-j", "route", "show", "dev", name)
	if err != nil {
		return InterfaceConfig{}, fmt.Errorf("ip route show %s: %w", name, err)
	}
	return parseIPState(name, addrOut, routeOut)
}

// parseIPState builds an InterfaceConfig from `ip -j addr` and `ip -j route`
// output. Link-scoped addresses (fe80::, scope "link") and connected/link routes
// (no gateway) are skipped — they are implied by the addresses, not desired
// state a caller sets. The "default" route populates Gateway; other gatewayed
// routes become Routes.
func parseIPState(name, addrJSON, routeJSON string) (InterfaceConfig, error) {
	cfg := InterfaceConfig{Name: name}

	var links []ipLink
	if err := json.Unmarshal([]byte(addrJSON), &links); err != nil {
		return InterfaceConfig{}, fmt.Errorf("parse ip addr JSON: %w", err)
	}
	if len(links) > 0 {
		cfg.MTU = links[0].MTU
		for _, a := range links[0].AddrInfo {
			if a.Scope == "link" || a.Local == "" {
				continue
			}
			cfg.Addresses = append(cfg.Addresses, fmt.Sprintf("%s/%d", a.Local, a.Prefixlen))
		}
	}

	var routes []ipRoute
	if err := json.Unmarshal([]byte(routeJSON), &routes); err != nil {
		return InterfaceConfig{}, fmt.Errorf("parse ip route JSON: %w", err)
	}
	for _, rt := range routes {
		if rt.Gateway == "" {
			continue // connected/link route, implied by the address
		}
		if rt.Dst == "default" {
			cfg.Gateway = rt.Gateway
			continue
		}
		cfg.Routes = append(cfg.Routes, Route{Destination: rt.Dst, Gateway: rt.Gateway, Metric: rt.Metric})
	}
	return cfg, nil
}
