package dns

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// etcResolvConfPath is the host's effective resolver file, which NetworkManager
// writes/manages. A package var so tests can point it at a fixture.
var etcResolvConfPath = "/etc/resolv.conf"

// nmManager drives DNS configuration via NetworkManager (nmcli). NetworkManager
// is connection-scoped: it configures DNS on the active connection of a device,
// so Config.Interface is REQUIRED (there is no clean host-global DNS via nmcli —
// use the Resolved backend for that).
type nmManager struct {
	r exec.Runner
}

// errInterfaceRequired is the shared "NM needs an interface" rejection.
func errInterfaceRequired() error {
	return fmt.Errorf("%w: the NetworkManager backend is connection-scoped and requires Config.Interface (use the Resolved backend for host-global DNS)", ErrInvalidConfig)
}

// Get reads the host's effective resolver configuration from /etc/resolv.conf
// (which NetworkManager writes/manages). This is the effective view across all
// connections — symmetric with the Resolved backend's Get — rather than a
// per-connection read (the Manager interface's Get carries no interface arg).
func (m *nmManager) Get(ctx context.Context) (State, error) {
	data, err := os.ReadFile(etcResolvConfPath)
	if err != nil {
		return State{}, fmt.Errorf("read %s: %w", etcResolvConfPath, err)
	}
	return parseResolvConf(data), nil
}

// Apply configures DNS on the active connection of cfg.Interface and reactivates
// it so the change takes effect.
func (m *nmManager) Apply(ctx context.Context, cfg Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.Interface == "" {
		return errInterfaceRequired()
	}

	conn, err := m.activeConnection(ctx, cfg.Interface)
	if err != nil {
		return err
	}

	args := []string{"connection", "modify", conn}
	v4, v6 := partitionByFamily(cfg.Nameservers)
	if len(v4) > 0 {
		args = append(args, "ipv4.dns", strings.Join(v4, ","))
	}
	if len(v6) > 0 {
		args = append(args, "ipv6.dns", strings.Join(v6, ","))
	}
	if len(cfg.SearchDomains) > 0 {
		domains := strings.Join(cfg.SearchDomains, ",")
		args = append(args, "ipv4.dns-search", domains, "ipv6.dns-search", domains)
	}

	if err := runPriv(ctx, m.r, "nmcli", args...); err != nil {
		return fmt.Errorf("nmcli connection modify %s: %w", conn, err)
	}
	if err := runPriv(ctx, m.r, "nmcli", "connection", "up", conn); err != nil {
		// Reactivation failed AFTER the modify, which NetworkManager has already
		// persisted — so the new (possibly attacker-influenced) DNS is now staged
		// in the saved profile and would take effect on the next activation. Roll
		// it back: clear the staged DNS fields so a failed apply leaves no
		// residual DNS mutation. Best-effort (the up failure is the reported
		// error); the rollback never re-introduces a custom resolver.
		_ = runPriv(ctx, m.r, "nmcli", "connection", "modify", conn,
			"ipv4.dns", "", "ipv6.dns", "", "ipv4.dns-search", "", "ipv6.dns-search", "")
		return fmt.Errorf("nmcli connection up %s: %w", conn, err)
	}
	return nil
}

// activeConnection resolves the connection name bound to iface. Returns an error
// if the interface has no active connection (nothing to modify).
//
// The resolved name comes from `nmcli ... device show` — UNTRUSTED host output —
// and is then placed on the argv of an escalated `connection modify` / `connection
// up`. A hostile or compromised NetworkManager (or a connection an attacker named)
// could emit a value that, fed back verbatim, smuggles a flag (a leading '-') or
// splits into extra tokens (an embedded newline/control char). The name is
// re-validated here, before any mutation, so host output can never become a
// privileged argv injection.
func (m *nmManager) activeConnection(ctx context.Context, iface string) (string, error) {
	out, err := runRead(ctx, m.r, "nmcli", "-g", "GENERAL.CONNECTION", "device", "show", iface)
	if err != nil {
		return "", fmt.Errorf("resolve connection for %s: %w", iface, err)
	}
	conn := strings.TrimSpace(out)
	if conn == "" || conn == "--" {
		return "", fmt.Errorf("%w: interface %q has no active NetworkManager connection to configure", ErrInvalidConfig, iface)
	}
	if err := validateConnName(conn); err != nil {
		return "", err
	}
	return conn, nil
}

// validateConnName re-validates an nmcli connection name read back from untrusted
// host output before it is used in an escalated mutation. A legitimate connection
// name may contain spaces ("Wired connection 1"), so spaces are allowed; but the
// name must not contain control characters (an embedded newline/CR/tab/NUL would
// split into extra argv tokens or corrupt line-oriented output) and must not begin
// with '-' (which nmcli would parse as a flag rather than a connection name).
func validateConnName(name string) error {
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: connection name %q from host output contains a control character", ErrInvalidConfig, name)
		}
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("%w: connection name %q from host output is flag-shaped (leading '-')", ErrInvalidConfig, name)
	}
	return nil
}
