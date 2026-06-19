package netconfig

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// networkDir is where systemd-networkd reads .network units. A package var so
// tests can assert the write path without a fixed root assumption.
var networkDir = "/etc/systemd/network"

// networkdBackend writes a managed .network unit and reloads networkd.
type networkdBackend struct {
	base
	fsm fsManager
}

// Apply validates cfg, writes /etc/systemd/network/<name>.network, and reloads
// networkd so the unit takes effect.
func (b *networkdBackend) Apply(ctx context.Context, cfg InterfaceConfig) error {
	if err := validateInterfaceConfig(cfg); err != nil {
		return err
	}
	body := renderNetworkUnit(cfg)
	path := networkDir + "/" + cfg.Name + ".network"
	if err := b.fsm.WriteFile(ctx, path, []byte(body), fs.WriteOptions{Mode: 0o644, Owner: "root", Group: "root"}); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := runPriv(ctx, b.r, "networkctl", "reload"); err != nil {
		return fmt.Errorf("networkctl reload: %w", err)
	}
	return nil
}

// renderNetworkUnit renders the .network unit for cfg. Values are validated
// (CIDRs/IP literals/ifname) before this runs, so none can carry a newline that
// would inject extra directives.
func renderNetworkUnit(cfg InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by power-manage-agent — do not edit by hand.\n")
	b.WriteString("[Match]\nName=" + cfg.Name + "\n\n")
	b.WriteString("[Network]\n")
	if cfg.Mode == DHCP {
		b.WriteString("DHCP=yes\n")
	} else {
		for _, a := range cfg.Addresses {
			b.WriteString("Address=" + a + "\n")
		}
		if cfg.Gateway != "" {
			b.WriteString("Gateway=" + cfg.Gateway + "\n")
		}
	}
	for _, d := range cfg.DNS {
		b.WriteString("DNS=" + d + "\n")
	}
	if cfg.MTU != 0 {
		b.WriteString("\n[Link]\nMTUBytes=" + strconv.Itoa(cfg.MTU) + "\n")
	}
	for _, rt := range cfg.Routes {
		b.WriteString("\n[Route]\n")
		// A "default" route omits Destination; networkd treats a [Route] with
		// only a Gateway as the default route for that gateway's family (so v4
		// and v6 defaults are both handled without guessing 0.0.0.0/0 vs ::/0).
		if rt.Destination != "default" {
			b.WriteString("Destination=" + rt.Destination + "\n")
		}
		b.WriteString("Gateway=" + rt.Gateway + "\n")
		if rt.Metric != 0 {
			b.WriteString("Metric=" + strconv.Itoa(rt.Metric) + "\n")
		}
	}
	return b.String()
}
