package firewall

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// ufw backend. ufw is Debian/Ubuntu's userspace wrapper over
// nftables/iptables. Like firewalld it expects to be the authoritative
// manager — writing rules directly with nft on a ufw host gets blown
// away the next time ufw reloads. So when ufw is the active manager,
// every Apply/Remove/List goes through the ufw CLI.
//
// Per-rule identity: ufw exposes a native `comment` flag on add. We
// reuse the same "pm:<name>" convention nftables and firewalld already
// use. `ufw status numbered` is the only programmatic path to a rule's
// index (which `ufw delete N` needs), so the lookup goes through a
// parser over that output.
//
// v1 scope is broader than firewalld's: ufw supports allow + deny
// natively and accepts source/dest scoping in its long-form syntax, so
// the full Rule struct round-trips with the only constraint shared with
// nftables: a Port set without a concrete Protocol is rejected
// (ufw would silently widen to tcp+udp).

const (
	ufwCommentPrefix = "pm:"
)

// ufwStatusRuleRE matches a single rule line in `ufw status numbered`
// output. Captures the rule number, the action verb (with optional
// IN/OUT direction), and the pm-suffixed comment. The middle columns
// are deliberately non-greedy and absorbed by `.*` because the goal of
// this regex is identity + verdict — Port/Protocol come from the To/From
// columns and are parsed by ufwParseRuleColumns when ufwParseStatus
// needs them for List.
var ufwStatusRuleRE = regexp.MustCompile(`^\[\s*(\d+)\]\s+(\S+)\s+(ALLOW|DENY|REJECT|LIMIT)(?:\s+(?:IN|OUT))?\s+(.+?)\s*#\s*pm:(\S+)\s*$`)

func applyUFW(ctx context.Context, rule Rule) error {
	if err := ufwValidateRule(rule); err != nil {
		return err
	}
	// Best-effort find-and-delete the previous rule by name. We do this
	// before the add so the final ruleset has exactly one rule per
	// Name — re-adding without delete would let stale variants
	// accumulate.
	if status, err := ufwStatusNumbered(ctx); err == nil {
		if num, ok := ufwFindRuleNumber(status, rule.Name); ok {
			if err := ufwDeleteByNumber(ctx, num); err != nil {
				return fmt.Errorf("ufw delete existing rule %d: %w", num, err)
			}
		}
	}
	args, err := ufwBuildAddArgs(rule)
	if err != nil {
		return err
	}
	if _, err := sysexec.Privileged(ctx, "ufw", args...); err != nil {
		return fmt.Errorf("ufw %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func removeUFW(ctx context.Context, name string) error {
	status, err := ufwStatusNumbered(ctx)
	if err != nil {
		// No status (likely ufw inactive) → no rule to remove. Matches
		// the idempotency contract: "this rule is absent" already holds.
		return nil
	}
	num, ok := ufwFindRuleNumber(status, name)
	if !ok {
		return nil
	}
	return ufwDeleteByNumber(ctx, num)
}

func listUFW(ctx context.Context) ([]Rule, error) {
	status, err := ufwStatusNumbered(ctx)
	if err != nil {
		// ufw not active → no managed rules.
		return nil, nil
	}
	return ufwParseStatus(status)
}

// ufwStatusNumbered runs `ufw status numbered` and returns its stdout.
// Goes through Privileged because ufw insists on root for status, even
// though the underlying kernel state is world-readable.
func ufwStatusNumbered(ctx context.Context) (string, error) {
	res, err := sysexec.Privileged(ctx, "ufw", "status", "numbered")
	if err != nil {
		return "", fmt.Errorf("ufw status numbered: %w", err)
	}
	return res.Stdout, nil
}

// ufwDeleteByNumber issues `ufw --force delete N`. The --force flag
// suppresses the "are you sure? (y/n)" prompt that would otherwise hang
// the call.
func ufwDeleteByNumber(ctx context.Context, num int) error {
	_, err := sysexec.Privileged(ctx, "ufw", "--force", "delete", strconv.Itoa(num))
	if err != nil {
		return fmt.Errorf("ufw --force delete %d: %w", num, err)
	}
	return nil
}

// ufwValidateRule enforces the v1 ufw scope: rule must say something
// meaningful (Port or Protocol or scoping), and a Port without a
// concrete Protocol is rejected for the same reason nftables rejects it.
func ufwValidateRule(rule Rule) error {
	if rule.Port > 0 && rule.Protocol == ProtocolAny {
		return fmt.Errorf("%w: port %d set without a concrete protocol; ufw requires tcp or udp", ErrInvalidRule, rule.Port)
	}
	if rule.Port == 0 && rule.Protocol == ProtocolAny && rule.Source == "" && rule.Dest == "" {
		return fmt.Errorf("%w: ufw rule needs at least Port, Protocol, Source, or Dest", ErrInvalidRule)
	}
	return nil
}

// ufwBuildAddArgs renders a Rule into the argv ufw expects on the CLI.
// Short form (`ufw allow PORT/PROTO`) when only Port+Protocol is set;
// long form (`ufw allow from SRC to DST port PORT proto PROTO`) the
// moment Source or Dest enters the picture. The comment is always last
// so a future ufw version that adds trailing positional args won't
// silently swallow it.
func ufwBuildAddArgs(rule Rule) ([]string, error) {
	if err := ufwValidateRule(rule); err != nil {
		return nil, err
	}
	verdict := "allow"
	if !rule.Allow {
		verdict = "deny"
	}
	args := []string{verdict}

	scoped := rule.Source != "" || rule.Dest != ""
	switch {
	case scoped:
		// Long form: from SRC to DST [port PORT] [proto PROTO].
		src := rule.Source
		if src == "" {
			src = "any"
		}
		dst := rule.Dest
		if dst == "" {
			dst = "any"
		}
		args = append(args, "from", src, "to", dst)
		if rule.Port > 0 {
			args = append(args, "port", strconv.Itoa(rule.Port))
		}
		if rule.Protocol == ProtocolTCP || rule.Protocol == ProtocolUDP {
			args = append(args, "proto", string(rule.Protocol))
		}
	case rule.Port > 0:
		// Short form: PORT/PROTO. Protocol is guaranteed concrete here
		// because ufwValidateRule rejected the any-proto case above.
		args = append(args, fmt.Sprintf("%d/%s", rule.Port, rule.Protocol))
	default:
		// Proto-only (no port, no scope). Short form doesn't accept
		// this; fall back to the long form with from/to any.
		args = append(args, "from", "any", "to", "any", "proto", string(rule.Protocol))
	}

	args = append(args, "comment", ufwCommentPrefix+rule.Name)
	return args, nil
}

// ufwFindRuleNumber scans `ufw status numbered` output and returns the
// rule index of the entry whose comment is "pm:<name>". ok=false when
// no such rule exists. Used by both ApplyRule (to remove a stale
// variant before re-adding) and RemoveRule (to find the target).
func ufwFindRuleNumber(status, name string) (int, bool) {
	for _, line := range strings.Split(status, "\n") {
		m := ufwStatusRuleRE.FindStringSubmatch(strings.TrimRight(line, " \t"))
		if m == nil {
			continue
		}
		if m[5] == name {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			return n, true
		}
	}
	return 0, false
}

// ufwParseStatus walks `ufw status numbered` output and returns the
// Rule struct for every pm-managed entry. Non-pm rules (the system's
// own ssh, dhcpv6-client, anything the operator added without our
// comment) are filtered out — same scope guarantee List makes on the
// nftables and firewalld backends.
func ufwParseStatus(status string) ([]Rule, error) {
	if strings.Contains(status, "Status: inactive") {
		return nil, nil
	}
	var rules []Rule
	for _, line := range strings.Split(status, "\n") {
		m := ufwStatusRuleRE.FindStringSubmatch(strings.TrimRight(line, " \t"))
		if m == nil {
			continue
		}
		rule := Rule{
			Name:  m[5],
			Allow: m[3] == "ALLOW",
		}
		// `To` column (m[2]) carries the port/proto in the unscoped
		// form ("22/tcp") or just the port ("53") for proto-any.
		ufwParseToColumn(m[2], &rule)
		// `From` column (m[4]) is "Anywhere" for unscoped rules, an
		// address/CIDR for scoped ones. Strip the trailing
		// whitespace the regex left behind.
		from := strings.TrimSpace(m[4])
		if from != "" && from != "Anywhere" && from != "Anywhere (v6)" {
			rule.Source = from
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ufwParseToColumn extracts port + protocol from the `To` column of a
// `ufw status numbered` line. Common shapes: "22/tcp", "53/udp",
// "Anywhere", or a host:port pair when the rule targets a specific
// dest. Anything we can't parse cleanly is left as zero-values on the
// Rule so List still returns the entry (its identity is the Name).
func ufwParseToColumn(col string, out *Rule) {
	col = strings.TrimSpace(col)
	if col == "Anywhere" || col == "Anywhere (v6)" {
		return
	}
	// "22/tcp" form.
	if slash := strings.Index(col, "/"); slash > 0 {
		if p, err := strconv.Atoi(col[:slash]); err == nil {
			out.Port = p
		}
		proto := col[slash+1:]
		if proto == "tcp" || proto == "udp" {
			out.Protocol = Protocol(proto)
		}
		return
	}
	// Bare port form (proto-any). Less common; we don't emit it but ufw
	// accepts operator-added rules in this shape.
	if p, err := strconv.Atoi(col); err == nil {
		out.Port = p
		return
	}
	// Otherwise treat as a destination address/CIDR.
	out.Dest = col
}
