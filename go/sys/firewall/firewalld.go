package firewall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	sysfs "github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// firewalld backend. Each Rule is materialised as a single custom
// firewalld service definition (XML at /etc/firewalld/services/pm-<name>.xml)
// and added to firewalld's default zone. The `pm-` prefix lets List
// pick power-manage-managed services out of the zone without
// touching system-installed ones (ssh, dhcpv6-client, etc.).
//
// v1 scope is deliberately narrow: simple Allow + Protocol +
// Port. Anything that needs a rich rule (deny, source/dest scope)
// surfaces as ErrInvalidRule with a clear "use a backend that
// supports this" hint. nftables is the v1 answer for those.
//
// Why services rather than rich rules: firewalld rich rules have no
// caller-friendly identity field (no comment, no name), so updating
// an existing rule programmatically requires string-matching the
// previous rendered form — fragile across firewalld versions. Custom
// services have a stable filesystem identity, idempotent enabling
// (--add-service is a no-op when already enabled), and a clean
// removal path.

const (
	firewalldServicesDir   = "/etc/firewalld/services"
	firewalldServicePrefix = "pm-"
)

// applyFirewalld installs or updates rule. Writes the service XML,
// reloads firewalld so the new definition is recognised, and adds it
// to the default zone (no-op if already present).
func applyFirewalld(ctx context.Context, rule Rule) error {
	if err := firewalldValidateRule(rule); err != nil {
		return err
	}
	zone, err := firewalldDefaultZone(ctx)
	if err != nil {
		return err
	}
	xml := firewalldServiceXML(rule)
	path := filepath.Join(firewalldServicesDir, firewalldServicePrefix+rule.Name+".xml")
	if err := sysfs.WriteFileAtomic(ctx, path, xml, "0644", "root", "root"); err != nil {
		return fmt.Errorf("write service xml %s: %w", path, err)
	}
	// Reload so the new service definition is parsed. Without this,
	// --add-service rejects the name.
	if _, err := sysexec.Privileged(ctx, "firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("firewall-cmd --reload: %w", err)
	}
	// --permanent so the change survives reboot; --add-service is
	// idempotent at the API level (no-op when already enabled).
	if _, err := sysexec.Privileged(ctx, "firewall-cmd",
		"--permanent", "--zone="+zone, "--add-service="+firewalldServicePrefix+rule.Name,
	); err != nil {
		return fmt.Errorf("firewall-cmd add-service: %w", err)
	}
	// Final reload so the runtime config matches permanent.
	if _, err := sysexec.Privileged(ctx, "firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("firewall-cmd --reload (post-enable): %w", err)
	}
	return nil
}

// removeFirewalld disables the service in the default zone and deletes
// its XML file. Missing services / files are no-ops, matching the
// idempotency contract.
func removeFirewalld(ctx context.Context, name string) error {
	zone, err := firewalldDefaultZone(ctx)
	if err != nil {
		return err
	}
	// Best-effort remove. firewall-cmd returns non-zero when the
	// service isn't enabled — that's fine, our post-condition holds.
	_, _ = sysexec.Privileged(ctx, "firewall-cmd",
		"--permanent", "--zone="+zone, "--remove-service="+firewalldServicePrefix+name,
	)
	path := filepath.Join(firewalldServicesDir, firewalldServicePrefix+name+".xml")
	if err := sysfs.RemoveStrict(ctx, path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	if _, err := sysexec.Privileged(ctx, "firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("firewall-cmd --reload: %w", err)
	}
	return nil
}

// listFirewalld returns every pm-managed service enabled in the
// default zone, reconstructed into Rule structs by reading each
// service's XML body.
func listFirewalld(ctx context.Context) ([]Rule, error) {
	zone, err := firewalldDefaultZone(ctx)
	if err != nil {
		return nil, err
	}
	res, err := sysexec.Privileged(ctx, "firewall-cmd",
		"--permanent", "--zone="+zone, "--list-services",
	)
	if err != nil {
		return nil, fmt.Errorf("firewall-cmd list-services: %w", err)
	}
	names := firewalldFilterPMServices(res.Stdout)
	rules := make([]Rule, 0, len(names))
	for _, name := range names {
		rule, ok := firewalldReadServiceRule(name)
		if !ok {
			// Service is enabled but its XML disappeared (operator
			// deleted by hand) — skip rather than fail the whole List.
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// firewalldValidateRule enforces the v1 scope: Allow=true,
// concrete Protocol, no source/dest. Everything else returns
// ErrInvalidRule with a hint naming the unsupported field, so the
// operator's error message tells them what to do instead of just
// "rejected."
func firewalldValidateRule(rule Rule) error {
	if !rule.Allow {
		return fmt.Errorf("%w: deny rules not supported by firewalld backend in v1 (use nftables)", ErrInvalidRule)
	}
	if rule.Source != "" {
		return fmt.Errorf("%w: source scoping not supported by firewalld backend in v1 (use nftables)", ErrInvalidRule)
	}
	if rule.Dest != "" {
		return fmt.Errorf("%w: destination scoping not supported by firewalld backend in v1 (use nftables)", ErrInvalidRule)
	}
	if rule.Protocol != ProtocolTCP && rule.Protocol != ProtocolUDP {
		return fmt.Errorf("%w: firewalld backend requires a concrete protocol (tcp or udp)", ErrInvalidRule)
	}
	if rule.Port <= 0 {
		return fmt.Errorf("%w: firewalld backend requires Port > 0", ErrInvalidRule)
	}
	return nil
}

// firewalldServiceXML renders a Rule into the XML body firewalld
// expects. Indentation matches the format `firewall-cmd
// --new-service-from-file` emits so a diff against an existing file
// reads cleanly to a human comparing the two.
func firewalldServiceXML(rule Rule) string {
	return strings.Join([]string{
		`<?xml version="1.0" encoding="utf-8"?>`,
		`<service>`,
		`  <short>pm:` + rule.Name + `</short>`,
		`  <description>power-manage managed rule</description>`,
		fmt.Sprintf(`  <port port="%d" protocol="%s"/>`, rule.Port, rule.Protocol),
		`</service>`,
		``,
	}, "\n")
}

// firewalldFilterPMServices extracts pm-managed service names from
// firewall-cmd's space-separated list-services output. Pure function —
// unit-tested without firewalld.
func firewalldFilterPMServices(out string) []string {
	fields := strings.Fields(out)
	var names []string
	for _, f := range fields {
		if name, ok := strings.CutPrefix(f, firewalldServicePrefix); ok {
			names = append(names, name)
		}
	}
	return names
}

// firewalldReadServiceRule reads a single pm-managed service's XML and
// reconstructs the Rule. Returns ok=false when the file is missing or
// the XML doesn't look like one we wrote.
func firewalldReadServiceRule(name string) (Rule, bool) {
	path := filepath.Join(firewalldServicesDir, firewalldServicePrefix+name+".xml")
	body, err := os.ReadFile(path) //nolint:gosec // path constructed from a validated name.
	if err != nil {
		return Rule{}, false
	}
	// Cheap text extraction rather than a full XML decode — the body
	// shape is fixed by firewalldServiceXML and the values are integer
	// + lowercase tcp/udp, so a regex-free scan is enough.
	rule := Rule{Name: name, Allow: true}
	if portIdx := strings.Index(string(body), `port port="`); portIdx >= 0 {
		rest := string(body)[portIdx+len(`port port="`):]
		end := strings.Index(rest, `"`)
		if end > 0 {
			if p, perr := strconv.Atoi(rest[:end]); perr == nil {
				rule.Port = p
			}
		}
	}
	if protoIdx := strings.Index(string(body), `protocol="`); protoIdx >= 0 {
		rest := string(body)[protoIdx+len(`protocol="`):]
		end := strings.Index(rest, `"`)
		if end > 0 {
			rule.Protocol = Protocol(rest[:end])
		}
	}
	if rule.Port == 0 || rule.Protocol == "" {
		return Rule{}, false
	}
	return rule, true
}

// firewalldDefaultZone queries firewall-cmd for the configured default
// zone. Caches nothing — `--get-default-zone` is a cheap call and
// operators changing the default zone at runtime should see the new
// answer on the next Apply.
func firewalldDefaultZone(ctx context.Context) (string, error) {
	res, err := sysexec.Privileged(ctx, "firewall-cmd", "--get-default-zone")
	if err != nil {
		return "", fmt.Errorf("firewall-cmd --get-default-zone: %w", err)
	}
	zone := strings.TrimSpace(res.Stdout)
	if zone == "" {
		return "", fmt.Errorf("firewall-cmd --get-default-zone returned empty output")
	}
	return zone, nil
}
