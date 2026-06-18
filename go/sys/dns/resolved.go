package dns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// resolvConfPath is systemd-resolved's generated resolv.conf, the authoritative
// view of the active resolver config. A package var so tests can point it at a
// fixture.
var resolvConfPath = "/run/systemd/resolve/resolv.conf"

// The managed global drop-in. A 10- prefix orders it before distro defaults
// without overriding a higher-numbered local override an admin may add.
const (
	resolvedDropInDir  = "/etc/systemd/resolved.conf.d"
	resolvedDropInPath = resolvedDropInDir + "/10-power-manage.conf"
)

// resolvedManager drives systemd-resolved via resolvectl plus a managed
// resolved.conf.d drop-in (written through the fs.Manager).
type resolvedManager struct {
	r   exec.Runner
	fsm fsManager
}

// Get reads and parses the active resolver configuration.
func (m *resolvedManager) Get(ctx context.Context) (State, error) {
	data, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return State{}, fmt.Errorf("read %s: %w", resolvConfPath, err)
	}
	return parseResolvConf(data), nil
}

// Apply validates cfg, then installs it. A scoped Interface uses runtime
// resolvectl per-link settings; an empty Interface writes the persistent global
// drop-in and restarts resolved to pick it up.
func (m *resolvedManager) Apply(ctx context.Context, cfg Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}

	if cfg.Interface != "" {
		if err := runPriv(ctx, m.r, "resolvectl", resolvectlDNSArgs(cfg.Interface, cfg.Nameservers)...); err != nil {
			return fmt.Errorf("resolvectl dns %s: %w", cfg.Interface, err)
		}
		if len(cfg.SearchDomains) > 0 {
			if err := runPriv(ctx, m.r, "resolvectl", resolvectlDomainArgs(cfg.Interface, cfg.SearchDomains)...); err != nil {
				return fmt.Errorf("resolvectl domain %s: %w", cfg.Interface, err)
			}
		}
		return nil
	}

	body, err := renderDropIn(cfg)
	if err != nil {
		return err
	}
	if err := m.fsm.Mkdir(ctx, resolvedDropInDir, fs.MkdirOptions{Mode: 0o755, Owner: "root", Group: "root", Recursive: true}); err != nil {
		return fmt.Errorf("create %s: %w", resolvedDropInDir, err)
	}
	if err := m.fsm.WriteFile(ctx, resolvedDropInPath, body, fs.WriteOptions{Mode: 0o644, Owner: "root", Group: "root"}); err != nil {
		return fmt.Errorf("write %s: %w", resolvedDropInPath, err)
	}
	if err := runPriv(ctx, m.r, "systemctl", "restart", "systemd-resolved"); err != nil {
		return fmt.Errorf("restart systemd-resolved: %w", err)
	}
	return nil
}

// resolvectlDNSArgs builds `resolvectl dns <iface> -- <ns...>`. The "--" keeps a
// nameserver beginning with "-" an operand (validation already rejects that, but
// the boundary stays fail-safe).
func resolvectlDNSArgs(iface string, nameservers []string) []string {
	return append([]string{"dns", iface}, exec.SeparatePositionals(nil, nameservers...)...)
}

// resolvectlDomainArgs builds `resolvectl domain <iface> -- <domains...>`.
func resolvectlDomainArgs(iface string, domains []string) []string {
	return append([]string{"domain", iface}, exec.SeparatePositionals(nil, domains...)...)
}

// renderDropIn builds the global drop-in content. A package var so a test can
// exercise Apply's render-error propagation, which is otherwise unreachable
// (validateConfig runs first and rejects the only render error).
var renderDropIn = renderResolvedDropIn

// renderResolvedDropIn renders the global resolved.conf.d drop-in. Values are
// already validated newline-free by validateConfig; the explicit guard here is
// defense-in-depth so a value can never inject extra [Resolve] directives into
// the root-parsed file.
func renderResolvedDropIn(cfg Config) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Managed by power-manage-agent — do not edit by hand.\n")
	b.WriteString("[Resolve]\n")
	if len(cfg.Nameservers) > 0 {
		v := strings.Join(cfg.Nameservers, " ")
		if strings.ContainsAny(v, "\n\r") {
			return nil, fmt.Errorf("%w: nameserver list contains a newline", ErrInvalidConfig)
		}
		b.WriteString("DNS=" + v + "\n")
	}
	if len(cfg.SearchDomains) > 0 {
		v := strings.Join(cfg.SearchDomains, " ")
		if strings.ContainsAny(v, "\n\r") {
			return nil, fmt.Errorf("%w: search-domain list contains a newline", ErrInvalidConfig)
		}
		b.WriteString("Domains=" + v + "\n")
	}
	return []byte(b.String()), nil
}

// parseResolvConf extracts nameservers and search domains from resolv.conf
// content. Comment lines (# or ;) and other directives (options, sortlist) are
// ignored. The last `search`/`domain` line wins, matching resolver(5).
func parseResolvConf(data []byte) State {
	var st State
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		// Drop an inline comment: everything from the first token that begins a
		// "#"/";" comment (a hand-edited resolv.conf may carry one). The keyword
		// (fields[0]) is never a comment — full-comment lines are skipped above —
		// so the cut is always at index >= 1 and fields stays non-empty.
		for i, f := range fields {
			if strings.HasPrefix(f, "#") || strings.HasPrefix(f, ";") {
				fields = fields[:i]
				break
			}
		}
		switch fields[0] {
		case "nameserver":
			if len(fields) >= 2 {
				st.Nameservers = append(st.Nameservers, fields[1])
			}
		case "search", "domain":
			st.SearchDomains = append([]string(nil), fields[1:]...)
		}
	}
	return st
}
