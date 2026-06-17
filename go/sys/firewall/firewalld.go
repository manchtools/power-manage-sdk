package firewall

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// firewalld is the firewall-cmd-backed Manager. Every mutating call is escalated
// through the injected Runner; service XML is written via the fs seams.
type firewalld struct {
	base
}

var _ Manager = (*firewalld)(nil)

// firewalld backend. Each Rule is materialised as a single custom
// firewalld service definition (XML at /etc/firewalld/services/<ns>-<id>.xml)
// and added to firewalld's default zone. The "<ns>-" prefix lets List
// pick this Manager's services out of the zone without touching
// system-installed ones (ssh, dhcpv6-client, etc.) or services owned by
// a different Manager.
//
// v1 scope is deliberately narrow: simple Allow + Protocol + Port.
// Anything that needs a rich rule (deny, source/dest scope) surfaces
// as ErrInvalidRule with a clear "use a backend that supports this"
// hint. nftables is the v1 answer for those.
//
// Why services rather than rich rules: firewalld rich rules have no
// caller-friendly identity field (no comment, no name), so updating
// an existing rule programmatically requires string-matching the
// previous rendered form — fragile across firewalld versions. Custom
// services have a stable filesystem identity, idempotent enabling
// (--add-service is a no-op when already enabled), and a clean
// removal path.

const firewalldServicesDir = "/etc/firewalld/services"

// firewalldServiceName composes the on-disk + firewall-cmd service name
// for a Rule in a given namespace. Format `<namespace>-<id>`.
func firewalldServiceName(namespace, id string) string {
	return namespace + "-" + id
}

// ApplyRule installs or updates rule. Writes the service XML, reloads firewalld
// so the new definition is recognised, and adds it to the default zone (no-op if
// already present).
func (f *firewalld) ApplyRule(ctx context.Context, rule Rule) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	if err := firewalldValidateRule(rule); err != nil {
		return err
	}
	zone, err := f.firewalldDefaultZone(ctx)
	if err != nil {
		return err
	}
	svc := firewalldServiceName(f.ns, rule.ID)
	xml := firewalldServiceXML(f.ns, rule)
	path := filepath.Join(firewalldServicesDir, svc+".xml")
	if err := f.fsm.WriteFile(ctx, path, []byte(xml), fs.WriteOptions{Mode: 0o644, Owner: "root", Group: "root"}); err != nil {
		return fmt.Errorf("write service xml %s: %w", path, err)
	}
	// Reload so the new service definition is parsed. Without this,
	// --add-service rejects the name.
	if _, err := f.run(ctx, "firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("firewall-cmd --reload: %w", err)
	}
	// --permanent so the change survives reboot; --add-service is
	// idempotent at the API level (no-op when already enabled).
	if _, err := f.run(ctx, "firewall-cmd",
		"--permanent", "--zone="+zone, "--add-service="+svc,
	); err != nil {
		return fmt.Errorf("firewall-cmd add-service: %w", err)
	}
	// Final reload so the runtime config matches permanent.
	if _, err := f.run(ctx, "firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("firewall-cmd --reload (post-enable): %w", err)
	}
	return nil
}

// RemoveRule disables the service in the default zone and deletes its XML file.
// Missing services / files are no-ops, matching the idempotency contract.
func (f *firewalld) RemoveRule(ctx context.Context, id string) error {
	if err := validateRuleID(id); err != nil {
		return err
	}
	zone, err := f.firewalldDefaultZone(ctx)
	if err != nil {
		return err
	}
	svc := firewalldServiceName(f.ns, id)

	// List services first so we can tell "service isn't enabled
	// (legitimate idempotency no-op)" apart from "firewall-cmd failed
	// for a real reason (daemon down, permission denied, syntax
	// error)". Just calling --remove-service and discarding errors
	// would swallow real failures and return success while the rule
	// is still enabled. String-matching the error message would work
	// but is fragile across firewalld versions and locales.
	enabled, err := f.firewalldServiceIsEnabled(ctx, zone, svc)
	if err != nil {
		return fmt.Errorf("firewall-cmd list-services: %w", err)
	}
	if enabled {
		if _, err := f.run(ctx, "firewall-cmd",
			"--permanent", "--zone="+zone, "--remove-service="+svc,
		); err != nil {
			return fmt.Errorf("firewall-cmd --remove-service: %w", err)
		}
	}
	path := filepath.Join(firewalldServicesDir, svc+".xml")
	// rm -f succeeds on an already-absent file, so a non-nil error is a real
	// failure (permission denied, etc.), not idempotent "not found".
	if err := f.fsm.Remove(ctx, path); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	if _, err := f.run(ctx, "firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("firewall-cmd --reload: %w", err)
	}
	return nil
}

// firewalldServiceIsEnabled reports whether svc is currently in the permanent
// service list for zone. Pre-check before --remove-service so RemoveRule can
// distinguish idempotency no-ops from real failures without parsing error
// messages.
func (f *firewalld) firewalldServiceIsEnabled(ctx context.Context, zone, svc string) (bool, error) {
	res, err := f.run(ctx, "firewall-cmd",
		"--permanent", "--zone="+zone, "--list-services",
	)
	if err != nil {
		return false, err
	}
	for _, field := range strings.Fields(res.Stdout) {
		if field == svc {
			return true, nil
		}
	}
	return false, nil
}

// List returns every managed service enabled in the default zone whose name
// starts with `<namespace>-`, reconstructed into Rule structs by reading each
// service's XML body.
func (f *firewalld) List(ctx context.Context) ([]Rule, error) {
	zone, err := f.firewalldDefaultZone(ctx)
	if err != nil {
		return nil, err
	}
	res, err := f.run(ctx, "firewall-cmd",
		"--permanent", "--zone="+zone, "--list-services",
	)
	if err != nil {
		return nil, fmt.Errorf("firewall-cmd list-services: %w", err)
	}
	ids := firewalldFilterNamespaceServices(res.Stdout, f.ns)
	rules := make([]Rule, 0, len(ids))
	for _, id := range ids {
		rule, ok := firewalldReadServiceRule(f.ns, id)
		if !ok {
			// Service is enabled but its XML disappeared (operator deleted by
			// hand) — skip rather than fail the whole List.
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// firewalldValidateRule enforces the v1 scope: Allow=true, concrete
// Protocol, no source/dest. Everything else returns ErrInvalidRule with
// a hint naming the unsupported field, so the operator's error message
// tells them what to do instead of just "rejected."
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
func firewalldServiceXML(namespace string, rule Rule) string {
	return strings.Join([]string{
		`<?xml version="1.0" encoding="utf-8"?>`,
		`<service>`,
		`  <short>` + firewalldServiceName(namespace, rule.ID) + `</short>`,
		`  <description>` + namespace + ` managed rule</description>`,
		fmt.Sprintf(`  <port port="%d" protocol="%s"/>`, rule.Port, rule.Protocol),
		`</service>`,
		``,
	}, "\n")
}

// firewalldFilterNamespaceServices extracts the per-namespace service
// suffixes from firewall-cmd's space-separated list-services output.
// Services whose name starts with "<namespace>-" are kept and the
// prefix is stripped; everything else (system services, services owned
// by a different Manager) is dropped. Pure function — unit-tested
// without firewalld.
func firewalldFilterNamespaceServices(out, namespace string) []string {
	prefix := namespace + "-"
	fields := strings.Fields(out)
	var ids []string
	for _, f := range fields {
		if id, ok := strings.CutPrefix(f, prefix); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// firewalldReadServiceRule reads a single managed service's XML and
// reconstructs the Rule. Returns ok=false when the file is missing or
// the XML doesn't look like one we wrote.
func firewalldReadServiceRule(namespace, id string) (Rule, bool) {
	path := filepath.Join(firewalldServicesDir, firewalldServiceName(namespace, id)+".xml")
	body, err := readFile(path) //nolint:gosec // path constructed from a validated namespace + id.
	if err != nil {
		return Rule{}, false
	}
	// Cheap text extraction rather than a full XML decode — the body
	// shape is fixed by firewalldServiceXML and the values are integer
	// + lowercase tcp/udp, so a regex-free scan is enough.
	rule := Rule{ID: id, Allow: true}
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
func (f *firewalld) firewalldDefaultZone(ctx context.Context) (string, error) {
	res, err := f.run(ctx, "firewall-cmd", "--get-default-zone")
	if err != nil {
		return "", fmt.Errorf("firewall-cmd --get-default-zone: %w", err)
	}
	zone := strings.TrimSpace(res.Stdout)
	if zone == "" {
		return "", fmt.Errorf("firewall-cmd --get-default-zone returned empty output")
	}
	return zone, nil
}
