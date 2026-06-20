package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// nftables backend. Each Manager owns a dedicated `inet <namespace>_filter`
// table with one `input` chain hooked at filter priority 0; every rule
// the Manager installs lives there. The table itself provides the
// namespace scoping — there is no need to tag rules with the namespace
// in their comments because querying `<namespace>_filter` only ever
// returns rules from this Manager's namespace.
//
// All mutations go through `nft -f -` (batch / stdin) so the kernel
// applies them in a single atomic transaction — partial state is never
// visible. The injected Runner handles sudo / doas elevation per the
// configured PrivilegeBackend.
type nftables struct {
	base
}

var _ Manager = (*nftables)(nil)

const (
	nftFamily = "inet"
	nftChain  = "input"
)

func nftTableName(namespace string) string {
	return namespace + "_filter"
}

// nftAddressFamily classifies a Source/Dest value as the nft address-
// family token it needs to be emitted under. Accepts both CIDR
// ("10.0.0.0/8", "2001:db8::/32") and bare IP ("10.0.0.1", "::1");
// returns ErrInvalidRule when the value parses as neither.
func nftAddressFamily(addr string) (string, error) {
	if ip, _, err := net.ParseCIDR(addr); err == nil {
		if ip.To4() != nil {
			return "ip", nil
		}
		return "ip6", nil
	}
	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() != nil {
			return "ip", nil
		}
		return "ip6", nil
	}
	return "", fmt.Errorf("%w: %q is not a valid IP address or CIDR", ErrInvalidRule, addr)
}

// ApplyRule installs or updates rule. The whole change (table + chain ensure,
// optional delete-of-previous, add) goes into one atomic `nft -f -` batch.
func (n *nftables) ApplyRule(ctx context.Context, rule Rule) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	// If a rule with this ID already exists, replace it in the same batch so the
	// kernel never sees "old gone but new not yet applied". A missing table
	// (list error) just means handle 0 = no delete.
	var handle int64
	if raw, lerr := n.nftListJSON(ctx); lerr == nil {
		if h, ok := nftFindRuleHandle(raw, rule.ID); ok {
			handle = h
		}
	}
	// Built once, after the handle is known, so there's a single source of the
	// nft-untranslatable rejection (port without protocol / mixed IP families).
	script, err := nftBuildApplyScriptStrict(n.ns, rule, handle)
	if err != nil {
		return err
	}
	return n.nftRunScript(ctx, script)
}

// RemoveRule deletes the rule with the given ID; a missing table or rule is a
// no-op (the post-condition "absent" already holds).
func (n *nftables) RemoveRule(ctx context.Context, id string) error {
	if err := validateRuleID(id); err != nil {
		return err
	}
	raw, err := n.nftListJSON(ctx)
	if err != nil {
		// No table → nothing to remove.
		return nil
	}
	handle, ok := nftFindRuleHandle(raw, id)
	if !ok {
		return nil
	}
	script := fmt.Sprintf("delete rule %s %s %s handle %d\n", nftFamily, nftTableName(n.ns), nftChain, handle)
	return n.nftRunScript(ctx, script)
}

// List returns every managed rule in this namespace's table.
func (n *nftables) List(ctx context.Context) ([]Rule, error) {
	raw, err := n.nftListJSON(ctx)
	if err != nil {
		// No table yet → no managed rules.
		return nil, nil
	}
	return nftParseRules(raw)
}

// nftListJSON runs `nft -j list table inet <namespace>_filter` and returns the
// raw JSON. Most distros restrict nft to root, so the call is escalated like
// every other op here. A non-zero exit (table missing) surfaces as an error the
// callers translate into "no managed rules".
func (n *nftables) nftListJSON(ctx context.Context) ([]byte, error) {
	res, err := n.run(ctx, "nft", "-j", "list", "table", nftFamily, nftTableName(n.ns))
	if err != nil {
		return nil, fmt.Errorf("nft list table: %w", err)
	}
	return []byte(res.Stdout), nil
}

// nftRunScript pipes a batch script into `nft -f -`. nft's transaction
// guarantees roll back the whole batch if any line fails.
func (n *nftables) nftRunScript(ctx context.Context, script string) error {
	if _, err := n.runStdin(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft -f -: %w", err)
	}
	return nil
}

// nftDeleteManagedTable removes this namespace's table; used by integration-test
// cleanup so each test starts on a fresh kernel.
func (n *nftables) nftDeleteManagedTable(ctx context.Context) error {
	script := fmt.Sprintf("delete table %s %s\n", nftFamily, nftTableName(n.ns))
	_, err := n.runStdin(ctx, script, "nft", "-f", "-")
	return err // missing table on the second teardown surfaces as a (harmless) error
}

// nftBuildApplyScript builds the batch script for an ApplyRule call,
// no validation beyond the dispatch layer's ID check. Used by the
// idempotency-test cases that exercise the builder's output shape.
func nftBuildApplyScript(namespace string, rule Rule, replaceHandle int64) string {
	script, _ := nftBuildApplyScriptStrict(namespace, rule, replaceHandle)
	return script
}

// nftBuildApplyScriptStrict errors on nft-untranslatable Rule combos —
// currently just "Port set without Protocol", which can't be expressed
// in one nft rule.
func nftBuildApplyScriptStrict(namespace string, rule Rule, replaceHandle int64) (string, error) {
	if rule.Port > 0 && rule.Protocol == ProtocolAny {
		return "", fmt.Errorf("%w: port %d set without a concrete protocol; nft requires tcp or udp", ErrInvalidRule, rule.Port)
	}

	table := nftTableName(namespace)
	var b strings.Builder
	// Table + chain exist after the first run, but `nft add table`
	// and `nft add chain` are no-ops when the object is already
	// present — cheaper than a list-first probe.
	fmt.Fprintf(&b, "add table %s %s\n", nftFamily, table)
	fmt.Fprintf(&b, "add chain %s %s %s { type filter hook input priority 0; policy accept; }\n",
		nftFamily, table, nftChain)

	// Replacing an existing rule means deleting it in the same batch
	// so the transaction stays atomic — at no point in the kernel
	// does the world see "old rule is gone but new isn't applied yet".
	if replaceHandle > 0 {
		fmt.Fprintf(&b, "delete rule %s %s %s handle %d\n",
			nftFamily, table, nftChain, replaceHandle)
	}

	var parts []string
	parts = append(parts, "add rule", nftFamily, table, nftChain)

	// Source / Dest may be IPv4 or IPv6 (CIDR or bare address). nft's
	// `inet` family carries both, but each match expression is family-
	// specific: `ip saddr` only matches IPv4 packets, `ip6 saddr` only
	// matches IPv6. Detect per side and emit the right token; if Source
	// and Dest disagree the rule could never match a real packet, so
	// reject it up front.
	var srcFam, dstFam string
	if rule.Source != "" {
		fam, err := nftAddressFamily(rule.Source)
		if err != nil {
			return "", fmt.Errorf("source %q: %w", rule.Source, err)
		}
		srcFam = fam
		parts = append(parts, fam, "saddr", rule.Source)
	}
	if rule.Dest != "" {
		fam, err := nftAddressFamily(rule.Dest)
		if err != nil {
			return "", fmt.Errorf("dest %q: %w", rule.Dest, err)
		}
		dstFam = fam
		parts = append(parts, fam, "daddr", rule.Dest)
	}
	if srcFam != "" && dstFam != "" && srcFam != dstFam {
		return "", fmt.Errorf("%w: source family %s differs from dest family %s; a rule that mixes IPv4 and IPv6 match expressions can never match a real packet", ErrInvalidRule, srcFam, dstFam)
	}
	if rule.Protocol == ProtocolTCP || rule.Protocol == ProtocolUDP {
		parts = append(parts, string(rule.Protocol))
		if rule.Port > 0 {
			parts = append(parts, "dport", fmt.Sprintf("%d", rule.Port))
		}
	}

	verdict := "accept"
	if !rule.Allow {
		verdict = "drop"
	}
	parts = append(parts, verdict)
	// The comment is just the rule ID — the table name carries the
	// namespace, so there's no need to repeat it here.
	parts = append(parts, "comment", fmt.Sprintf(`"%s"`, rule.ID))

	// Single space joins are safe because every part is either a
	// fixed keyword or a value already validated upstream (CIDR,
	// integer, ID regex).
	b.WriteString(strings.Join(parts, " "))
	b.WriteString("\n")
	return b.String(), nil
}

// =============================================================================
// JSON-shaped helpers — pure functions, easy to unit-test against
// captured nft output.
// =============================================================================

// nftRuleObject is the shape of a single "rule": ... entry inside nft's
// `-j` output. Only the fields List + idempotency lookup care about
// are decoded; everything else stays in the json.RawMessage so we
// don't break when nft adds new keys.
type nftRuleObject struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Handle  int64             `json:"handle"`
	Comment string            `json:"comment"`
	Expr    []json.RawMessage `json:"expr"`
}

// nftListItem matches the discriminated-union top-level entries in
// nft's output — each item has exactly one populated field.
type nftListItem struct {
	Table *json.RawMessage `json:"table,omitempty"`
	Chain *json.RawMessage `json:"chain,omitempty"`
	Rule  *nftRuleObject   `json:"rule,omitempty"`
}

type nftListEnvelope struct {
	Nftables []nftListItem `json:"nftables"`
}

// nftParseRules decodes nft's -j output and returns the Rule structs
// for every rule it finds. Since the caller already queried the
// Manager's namespaced table, every returned rule is in-namespace by
// construction — no comment-prefix filtering needed.
func nftParseRules(raw []byte) ([]Rule, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var env nftListEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("unmarshal nft list: %w", err)
	}
	var rules []Rule
	for _, item := range env.Nftables {
		if item.Rule == nil {
			continue
		}
		// Rules without a comment are either system-installed or
		// operator-added inside our table. Skip rather than treat them
		// as managed.
		if item.Rule.Comment == "" {
			continue
		}
		rule := Rule{ID: item.Rule.Comment}
		applyExprToRule(item.Rule.Expr, &rule)
		rules = append(rules, rule)
	}
	return rules, nil
}

// nftFindRuleHandle returns the handle of the first rule whose comment
// matches id. ok=false when no such rule exists.
func nftFindRuleHandle(raw []byte, id string) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var env nftListEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0, false
	}
	for _, item := range env.Nftables {
		if item.Rule == nil {
			continue
		}
		if item.Rule.Comment == id {
			return item.Rule.Handle, true
		}
	}
	return 0, false
}

// applyExprToRule decodes the parts of an nft rule's `expr` array we
// care about: the protocol+port match and the accept/drop verdict.
// Anything else (counters, log, future stmts) is ignored.
//
// The verdict decode uses json.RawMessage rather than *struct{} so
// that nft's `"accept": null` form is correctly recognised as
// "accept-key is present" — a *struct{} pointer would stay nil for
// a null value and silently fall through to the drop branch.
func applyExprToRule(expr []json.RawMessage, out *Rule) {
	for _, e := range expr {
		var verdict struct {
			Accept json.RawMessage `json:"accept,omitempty"`
			Drop   json.RawMessage `json:"drop,omitempty"`
		}
		if err := json.Unmarshal(e, &verdict); err == nil {
			if verdict.Accept != nil {
				out.Allow = true
			} else if verdict.Drop != nil {
				out.Allow = false
			}
		}
		var match struct {
			Match *struct {
				Op   string `json:"op"`
				Left struct {
					Payload *struct {
						Protocol string `json:"protocol"`
						Field    string `json:"field"`
					} `json:"payload"`
				} `json:"left"`
				Right json.RawMessage `json:"right"`
			} `json:"match"`
		}
		if err := json.Unmarshal(e, &match); err == nil && match.Match != nil {
			if pl := match.Match.Left.Payload; pl != nil {
				switch pl.Field {
				case "dport":
					out.Protocol = Protocol(pl.Protocol)
					var port int
					_ = json.Unmarshal(match.Match.Right, &port)
					out.Port = port
				case "saddr":
					out.Source = nftDecodeAddr(match.Match.Right)
				case "daddr":
					out.Dest = nftDecodeAddr(match.Match.Right)
				}
			}
		}
	}
}

// nftDecodeAddr renders an nft match right-hand side back to the SDK's
// address/CIDR string. nft emits a bare address as a JSON string
// ("10.0.0.1") and a network as {"prefix":{"addr":"10.0.0.0","len":24}}.
// Without this, List dropped a rule's Source/Dest (returned ""), so a rule
// that filters on an address round-tripped as "any" — a real fidelity bug the
// fake-runner tests missed and the real-nft container round-trip caught.
func nftDecodeAddr(raw json.RawMessage) string {
	var bare string
	if err := json.Unmarshal(raw, &bare); err == nil {
		return bare
	}
	var p struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if err := json.Unmarshal(raw, &p); err == nil && p.Prefix != nil {
		return fmt.Sprintf("%s/%d", p.Prefix.Addr, p.Prefix.Len)
	}
	return ""
}
