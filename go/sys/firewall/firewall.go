package firewall

// Package-level documentation lives in doc.go.

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
	// BackendIptables is Linux iptables (iptables-legacy or iptables-nft).
	BackendIptables Backend = 1
	// BackendFirewalld is the firewalld wrapper common on Red Hat family.
	BackendFirewalld Backend = 2
	// BackendUFW is Debian/Ubuntu's ufw wrapper.
	BackendUFW Backend = 3
	// BackendPF is the BSD packet filter.
	BackendPF Backend = 4
)

// ErrBackendNotSupported is returned when a caller invokes an operation
// on a backend that has no concrete implementation yet.
var ErrBackendNotSupported = errors.New("firewall backend not supported")

// ErrInvalidRule is returned by Manager methods when the Rule fails
// backend-independent validation — most often a Rule.ID that doesn't
// match the safe-identifier regex.
var ErrInvalidRule = errors.New("invalid firewall rule")

// ErrInvalidNamespace is returned by New when the caller-supplied
// namespace doesn't match the safe-identifier regex.
var ErrInvalidNamespace = errors.New("invalid firewall namespace")

// namespaceRE constrains the per-Manager namespace to a backend-safe
// subset: lowercase letter start, then lowercase/digit/underscore. No
// hyphens, no colons — those are reserved as separators when the
// namespace is composed with a Rule.ID into a backend identity string
// (e.g. nft table names disallow hyphens in some grammars; reserving
// the separator keeps parsing unambiguous everywhere).
var namespaceRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// ruleIDRE constrains Rule.ID to a backend-safe subset. Lowercase
// alphanum start, then lowercase/digit/hyphen/underscore. Hyphens are
// allowed inside an ID (callers commonly compose IDs from an
// action-style ULID plus a suffix like "-allow-22"), but the leading
// char excludes hyphen so a stray ID can't look like a CLI flag.
var ruleIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func validateNamespace(ns string) error {
	if ns == "" {
		return fmt.Errorf("%w: namespace is empty", ErrInvalidNamespace)
	}
	if !namespaceRE.MatchString(ns) {
		return fmt.Errorf("%w: %q must match %s", ErrInvalidNamespace, ns, namespaceRE.String())
	}
	return nil
}

func validateRuleID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: rule ID is empty", ErrInvalidRule)
	}
	if !ruleIDRE.MatchString(id) {
		return fmt.Errorf("%w: ID %q must match %s", ErrInvalidRule, id, ruleIDRE.String())
	}
	return nil
}

var backend atomic.Int32

// SetBackend selects the active backend for every Manager in the
// process. Call once at startup. Backend selection is host-level (a
// single host runs at most one active packet-filter manager), so the
// atomic process-wide variable matches the deployment reality even
// though namespacing is per-Manager.
//
// Unknown values are ignored so a zero-valued Backend enum cannot
// silently regress an explicitly-set backend.
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
// surface stays intentionally minimal — implementations translate it
// into the backend's native grammar (chains + priorities for nft,
// zones + services for firewalld, numbered rules for ufw).
//
// Idempotency: ID is the key every backend uses to find a previously
// installed rule. Manager.ApplyRule with an existing ID updates the
// rule in place; Manager.RemoveRule on a missing ID is a no-op. ID is
// opaque to the SDK — pick whatever scheme fits the application
// (a ULID, a UUID, a hierarchical path, a hash). The on-host identity
// stored by every backend is derived from the Manager's namespace plus
// this ID, so two Managers with different namespaces will never see
// each other's rules even if they choose the same ID.
//
// ID must match `^[a-z0-9][a-z0-9_-]{0,62}$` so it round-trips through
// nft comments, firewalld service names, and ufw comments without
// per-backend escaping.
type Rule struct {
	ID       string   // Stable, namespace-scoped identifier.
	Allow    bool     // true = allow, false = deny.
	Protocol Protocol // tcp / udp / "" (any).
	Port     int      // 0 = any.
	Source   string   // IPv4/IPv6 CIDR or address; empty = any.
	Dest     string   // IPv4/IPv6 CIDR or address; empty = any.
}

// Manager owns a namespaced set of firewall rules. Two Managers with
// different namespaces are isolated: each one's List, ApplyRule, and
// RemoveRule only see and touch rules in its own namespace. Other rules
// on the host (system-installed, operator-added, or owned by a different
// caller) stay invisible and untouched.
//
// Manager is safe for concurrent use by multiple goroutines; the
// underlying CLI tools (nft, firewall-cmd, ufw) are themselves not
// guaranteed reentrant, so simultaneous mutations from many goroutines
// may serialise inside the OS.
type Manager struct {
	namespace string
}

// New constructs a Manager for the given namespace. The namespace
// scopes List, ApplyRule, and RemoveRule, and is also used as the
// prefix for every rule's on-host identity (e.g. nft owns a dedicated
// table named `<namespace>_filter`; firewalld services are named
// `<namespace>-<rule.ID>`; ufw comments are `<namespace>:<rule.ID>`).
//
// namespace must match `^[a-z][a-z0-9_]{0,30}$`. The 31-char cap and
// the 63-char Rule.ID cap together leave room for the separators every
// backend needs (the nft table-name grammar, the firewalld service-name
// grammar, the 128-byte nft comment field).
func New(namespace string) (*Manager, error) {
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}
	return &Manager{namespace: namespace}, nil
}

// Namespace returns the namespace this Manager was constructed with.
// Read-only; immutable for the lifetime of the Manager.
func (m *Manager) Namespace() string { return m.namespace }

// ApplyRule installs or updates a rule. Identified by Rule.ID so
// reapplying the same rule is idempotent — backends find the previous
// rule by ID and update it in place. Returns ErrInvalidRule for IDs
// that fail validation and ErrBackendNotSupported when the active
// backend has no implementation.
func (m *Manager) ApplyRule(ctx context.Context, rule Rule) error {
	if err := validateRuleID(rule.ID); err != nil {
		return err
	}
	switch CurrentBackend() {
	case BackendNftables:
		return applyNftables(ctx, m.namespace, rule)
	case BackendFirewalld:
		return applyFirewalld(ctx, m.namespace, rule)
	case BackendUFW:
		return applyUFW(ctx, m.namespace, rule)
	default:
		return unsupported("ApplyRule")
	}
}

// RemoveRule removes a rule by ID. Missing rules are a no-op (the
// post-condition "this rule is absent" already holds). Validates the
// ID with the same regex as ApplyRule so a caller can't smuggle
// backend-grammar-breaking input through the inverse path.
func (m *Manager) RemoveRule(ctx context.Context, id string) error {
	if err := validateRuleID(id); err != nil {
		return err
	}
	switch CurrentBackend() {
	case BackendNftables:
		return removeNftables(ctx, m.namespace, id)
	case BackendFirewalld:
		return removeFirewalld(ctx, m.namespace, id)
	case BackendUFW:
		return removeUFW(ctx, m.namespace, id)
	default:
		return unsupported("RemoveRule")
	}
}

// List returns every rule the Manager currently owns. Rules outside
// this Manager's namespace (system-installed, owned by a different
// Manager, operator-added) are not returned — the inspection surface
// stays scoped to what this caller actually owns, so callers can't
// accidentally mutate rules they didn't install.
//
// Order is not guaranteed across calls; sort if you need stability.
func (m *Manager) List(ctx context.Context) ([]Rule, error) {
	switch CurrentBackend() {
	case BackendNftables:
		return listNftables(ctx, m.namespace)
	case BackendFirewalld:
		return listFirewalld(ctx, m.namespace)
	case BackendUFW:
		return listUFW(ctx, m.namespace)
	default:
		return nil, unsupported("List")
	}
}
