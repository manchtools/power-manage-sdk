// Package firewall is a forward-compat extension point for packet-
// filter management. Backend selector is in place; implementations
// land as features ship.
//
// See docs/backend-pattern.md for why every sys/* package that
// abstracts over multiple implementations follows this same shape.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync/atomic"
)

// Backend identifies which packet-filter framework the SDK targets.
type Backend int

const (
	// BackendNftables is Linux nftables via nft(8). Default — the modern
	// Linux firewall framework that iptables is migrating toward.
	BackendNftables Backend = 0
	// BackendIptables is Linux iptables (iptables-legacy or iptables-nft
	// translation shim).
	BackendIptables Backend = 1
	// BackendFirewalld is the firewalld wrapper common on Red Hat family.
	BackendFirewalld Backend = 2
	// BackendUFW is Debian/Ubuntu's ufw wrapper.
	BackendUFW Backend = 3
	// BackendPF is the BSD packet filter.
	BackendPF Backend = 4
)

// ErrBackendNotSupported is returned when a caller invokes an
// operation on a backend that has no concrete implementation yet.
var ErrBackendNotSupported = errors.New("firewall backend not supported")

// ErrInvalidRule is returned by ApplyRule / RemoveRule when the Rule
// fails backend-independent validation — most often a Name that
// contains a character backends would have to escape in their native
// grammar (whitespace, quotes, shell-metas, control characters) or
// that is empty / over the length cap.
//
// Callers use errors.Is(err, ErrInvalidRule) to distinguish operator
// error from backend-side failures.
var ErrInvalidRule = errors.New("invalid firewall rule")

// ruleNameRE constrains rule names to a safe ASCII subset so they can
// be round-tripped through nft's comment field, firewalld's rich-rule
// comment, and ufw's annotated rule format without needing per-backend
// quoting. Letters, digits, dash, underscore, and dot. 1–63 chars
// matches typical DNS-style labels operators are used to.
var ruleNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)

// validateRuleName runs the backend-independent checks every entry
// point shares. Kept as a helper so List can grow into "filter by
// name" without duplicating the regex.
func validateRuleName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidRule)
	}
	if !ruleNameRE.MatchString(name) {
		return fmt.Errorf("%w: name %q must match %s", ErrInvalidRule, name, ruleNameRE.String())
	}
	return nil
}

var backend atomic.Int32

// SetBackend selects the active backend. Call once at startup. Unknown
// values are ignored so a zero-valued Backend enum cannot silently
// regress an explicitly-set backend.
func SetBackend(b Backend) {
	switch b {
	case BackendNftables, BackendIptables, BackendFirewalld, BackendUFW, BackendPF:
		backend.Store(int32(b))
	}
}

// CurrentBackend returns the active backend.
func CurrentBackend() Backend {
	return Backend(backend.Load())
}

// String renders the backend as its canonical tool name.
func (b Backend) String() string {
	switch b {
	case BackendNftables:
		return "nftables"
	case BackendIptables:
		return "iptables"
	case BackendFirewalld:
		return "firewalld"
	case BackendUFW:
		return "ufw"
	case BackendPF:
		return "pf"
	default:
		return fmt.Sprintf("unknown(%d)", int(b))
	}
}

func unsupported(op string) error {
	return fmt.Errorf("%w: %s on backend %s", ErrBackendNotSupported, op, CurrentBackend())
}

// Protocol names a network protocol for rule matching.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
	ProtocolAny Protocol = ""
)

// Rule describes a single allow-or-deny decision. The cross-backend
// surface stays intentionally minimal — implementations translate
// into the backend's native grammar (chains + priorities for nft,
// zones for firewalld, numbered rules for ufw, etc.).
//
// Idempotency: Name is the key every backend uses to find a previously
// installed rule. ApplyRule with an existing Name updates the rule in
// place; RemoveRule with a missing Name is a no-op. Name must match
// `^[A-Za-z0-9._-]{1,63}$` so backends can round-trip it through their
// native comment / annotation field without per-backend escaping.
type Rule struct {
	Name     string   // Stable identifier; matches ruleNameRE.
	Allow    bool     // true = allow, false = deny
	Protocol Protocol // tcp / udp / any
	Port     int      // 0 = any
	Source   string   // CIDR or address; empty = any
	Dest     string   // CIDR or address; empty = any
	Comment  string   // Written into the backend's comment field where supported
}

// ApplyRule installs or updates a rule. Identified by Rule.Name so
// reapplying the same rule is idempotent. Returns ErrInvalidRule for
// names that fail validation (callers branch on this to distinguish
// operator error from backend failure) and ErrBackendNotSupported when
// the active backend has no impl.
func ApplyRule(ctx context.Context, rule Rule) error {
	if err := validateRuleName(rule.Name); err != nil {
		return err
	}
	switch CurrentBackend() {
	case BackendNftables:
		return applyNftables(ctx, rule)
	default:
		return unsupported("ApplyRule")
	}
}

// RemoveRule removes a rule by name. Missing rules are a no-op (the
// post-condition "this rule is absent" already holds). Validates the
// name with the same regex as ApplyRule so a caller can't smuggle
// backend-grammar-breaking input through the inverse path.
func RemoveRule(ctx context.Context, name string) error {
	if err := validateRuleName(name); err != nil {
		return err
	}
	switch CurrentBackend() {
	case BackendNftables:
		return removeNftables(ctx, name)
	default:
		return unsupported("RemoveRule")
	}
}

// List returns every power-manage-managed rule the active backend
// currently has installed. Rules outside the power-manage namespace
// (system-installed nft tables, firewalld's default zones, etc.) are
// not returned — the inspection surface stays scoped to what
// power-manage actually owns, so callers don't accidentally mutate
// system rules they didn't put there.
//
// Order is not guaranteed across calls; sort if you need stability.
func List(ctx context.Context) ([]Rule, error) {
	switch CurrentBackend() {
	case BackendNftables:
		return listNftables(ctx)
	default:
		return nil, unsupported("List")
	}
}

// Reload re-applies the active ruleset. Useful after bulk changes
// where callers want one atomic transaction rather than ApplyRule x N.
func Reload(ctx context.Context) error {
	switch CurrentBackend() {
	default:
		return unsupported("Reload")
	}
}
