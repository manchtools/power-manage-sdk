package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
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
// visible. The wrapper `exec.Privileged` handles sudo / doas
// elevation per the active PrivilegeBackend.

const (
	nftFamily = "inet"
	nftChain  = "input"
)

func nftTableName(namespace string) string {
	return namespace + "_filter"
}

func applyNftables(ctx context.Context, namespace string, rule Rule) error {
	script, err := nftBuildApplyScriptStrict(namespace, rule, 0)
	if err != nil {
		return err
	}
	// Translate "" into 0 (no delete) without surfacing the empty
	// listing as an error.
	if raw, lerr := nftListJSON(ctx, namespace); lerr == nil {
		if handle, ok := nftFindRuleHandle(raw, rule.ID); ok {
			script, err = nftBuildApplyScriptStrict(namespace, rule, handle)
			if err != nil {
				return err
			}
		}
	}
	return nftRunScript(ctx, script)
}

func removeNftables(ctx context.Context, namespace, id string) error {
	raw, err := nftListJSON(ctx, namespace)
	if err != nil {
		// No table → nothing to remove.
		return nil
	}
	handle, ok := nftFindRuleHandle(raw, id)
	if !ok {
		return nil
	}
	script := fmt.Sprintf("delete rule %s %s %s handle %d\n", nftFamily, nftTableName(namespace), nftChain, handle)
	return nftRunScript(ctx, script)
}

func listNftables(ctx context.Context, namespace string) ([]Rule, error) {
	raw, err := nftListJSON(ctx, namespace)
	if err != nil {
		// No table yet → no managed rules.
		return nil, nil
	}
	return nftParseRules(raw)
}

// nftListJSON runs `nft -j list table inet <namespace>_filter` and
// returns the raw JSON. The query is unprivileged in principle but in
// practice most distros restrict nft to root, so the call goes through
// exec.Privileged like every other op in this file.
func nftListJSON(ctx context.Context, namespace string) ([]byte, error) {
	res, err := sysexec.Privileged(ctx, "nft", "-j", "list", "table", nftFamily, nftTableName(namespace))
	if err != nil {
		return nil, fmt.Errorf("nft list table: %w", err)
	}
	return []byte(res.Stdout), nil
}

// nftRunScript pipes a batch script into `nft -f -`. The script is
// applied atomically; nft's transaction guarantees roll back the
// whole batch if any line fails to parse or apply.
func nftRunScript(ctx context.Context, script string) error {
	_, err := sysexec.PrivilegedWithStdin(ctx, strings.NewReader(script), "nft", "-f", "-")
	if err != nil {
		return fmt.Errorf("nft -f -: %w", err)
	}
	return nil
}

// nftDeleteManagedTable removes this namespace's table; used by test
// cleanup so each test starts on a fresh kernel.
func nftDeleteManagedTable(ctx context.Context, namespace string) error {
	script := fmt.Sprintf("delete table %s %s\n", nftFamily, nftTableName(namespace))
	_, err := sysexec.PrivilegedWithStdin(ctx, strings.NewReader(script), "nft", "-f", "-")
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

	if rule.Source != "" {
		parts = append(parts, "ip", "saddr", rule.Source)
	}
	if rule.Dest != "" {
		parts = append(parts, "ip", "daddr", rule.Dest)
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
			if pl := match.Match.Left.Payload; pl != nil && pl.Field == "dport" {
				out.Protocol = Protocol(pl.Protocol)
				var port int
				_ = json.Unmarshal(match.Match.Right, &port)
				out.Port = port
			}
		}
	}
}
