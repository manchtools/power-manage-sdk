package firewall

// Package-level documentation lives in doc.go.

import (
	"context"
	"errors"
	"fmt"
	"net"
	osexec "os/exec"
	"regexp"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// Backend selects the packet-filter framework the SDK targets. Passed explicitly
// to New; the zero value is invalid (New → ErrUnknownBackend). The
// never-implemented iptables/pf scaffolds are not ported; a real fourth backend
// is appended here when actually written.
type Backend int

const (
	// Nftables is Linux nftables via nft(8) — the modern framework iptables is
	// migrating toward. Each Manager owns a dedicated `inet <namespace>_filter`
	// table.
	Nftables Backend = iota + 1
	// Firewalld wraps firewall-cmd (Red Hat family). Each rule becomes a custom
	// service in the default zone. v1 scope: allow-only, concrete tcp/udp, port.
	Firewalld
	// UFW wraps ufw(8) (Debian/Ubuntu). Identity is the native comment field.
	UFW
)

// String renders the backend as its canonical tool name.
func (b Backend) String() string {
	switch b {
	case Nftables:
		return "nftables"
	case Firewalld:
		return "firewalld"
	case UFW:
		return "ufw"
	default:
		return fmt.Sprintf("unknown(%d)", int(b))
	}
}

// ErrUnknownBackend is returned by New for the zero value or any Backend the SDK
// does not implement (fail-closed).
var ErrUnknownBackend = errors.New("firewall: unknown backend")

// ErrInvalidRule is returned by Manager methods when a Rule fails validation —
// the backend-independent checks (ID/port/protocol/addr) or a backend-specific
// scope limit (e.g. a deny rule on the firewalld v1 backend).
var ErrInvalidRule = errors.New("invalid firewall rule")

// ErrInvalidNamespace is returned by New when the namespace fails validation.
var ErrInvalidNamespace = errors.New("invalid firewall namespace")

// namespaceRE constrains the per-Manager namespace to a backend-safe subset:
// lowercase letter start, then lowercase/digit/underscore. No hyphens or colons
// — those are reserved as separators when the namespace is composed with a
// Rule.ID into a backend identity string.
var namespaceRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// ruleIDRE constrains Rule.ID to a backend-safe subset. Hyphens are allowed
// inside an ID (callers compose IDs from a ULID plus a suffix like "-allow-22"),
// but the leading char excludes hyphen so a stray ID can't look like a CLI flag.
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

// validatePort enforces 0 ≤ port ≤ 65535. Port 0 is the "any port" sentinel; any
// negative or out-of-range value is rejected here so every backend gets the same
// reply.
func validatePort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("%w: port %d outside valid TCP/UDP range 0..65535", ErrInvalidRule, port)
	}
	return nil
}

// validateProtocol restricts Protocol to the SDK's three canonical values so the
// backend dispatch only ever sees one of the expected three.
func validateProtocol(p Protocol) error {
	switch p {
	case ProtocolTCP, ProtocolUDP, ProtocolAny:
		return nil
	default:
		return fmt.Errorf("%w: protocol %q must be one of %q / %q / %q (any)",
			ErrInvalidRule, p, ProtocolTCP, ProtocolUDP, ProtocolAny)
	}
}

// validateAddr accepts an empty string (the "any address" sentinel), a bare IP
// literal (v4 or v6), or a CIDR. Anything else — hostnames, garbage,
// shell-shape strings — is refused.
func validateAddr(field, addr string) error {
	if addr == "" {
		return nil
	}
	if _, _, err := net.ParseCIDR(addr); err == nil {
		return nil
	}
	if net.ParseIP(addr) != nil {
		return nil
	}
	return fmt.Errorf("%w: %s %q is not a valid IP address or CIDR", ErrInvalidRule, field, addr)
}

// validateRule runs every backend-independent invariant a Rule must satisfy
// before dispatch. Called at the top of every backend's ApplyRule so all three
// inherit the same rejection contract. Backend-specific rejections (firewalld's
// allow-only scope, nft's "port without protocol") layer on top in the backend's
// own validator.
func validateRule(rule Rule) error {
	if err := validateRuleID(rule.ID); err != nil {
		return err
	}
	if err := validatePort(rule.Port); err != nil {
		return err
	}
	if err := validateProtocol(rule.Protocol); err != nil {
		return err
	}
	if err := validateAddr("source", rule.Source); err != nil {
		return err
	}
	if err := validateAddr("dest", rule.Dest); err != nil {
		return err
	}
	return nil
}

// Protocol names a network protocol for rule matching.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
	ProtocolAny Protocol = ""
)

// Rule describes a single allow-or-deny decision. The cross-backend surface
// stays intentionally minimal — implementations translate it into the backend's
// native grammar (chains + priorities for nft, zones + services for firewalld,
// numbered rules for ufw).
//
// Idempotency: ID is the key every backend uses to find a previously installed
// rule. ApplyRule with an existing ID updates the rule in place; RemoveRule on a
// missing ID is a no-op. ID is opaque to the SDK — pick whatever scheme fits
// (a ULID, a UUID, a path, a hash). The on-host identity stored by every backend
// is derived from the Manager's namespace plus this ID, so two Managers with
// different namespaces never see each other's rules even with the same ID.
//
// ID must match `^[a-z0-9][a-z0-9_-]{0,62}$` so it round-trips through nft
// comments, firewalld service names, and ufw comments without per-backend
// escaping.
type Rule struct {
	ID       string   // stable, namespace-scoped identifier
	Allow    bool     // true = allow, false = deny
	Protocol Protocol // tcp / udp / "" (any)
	Port     int      // 0 = any
	Source   string   // IPv4/IPv6 CIDR or address; empty = any
	Dest     string   // IPv4/IPv6 CIDR or address; empty = any
}

// Manager owns a namespaced set of firewall rules. Two Managers with different
// namespaces are isolated: each one's List, ApplyRule, and RemoveRule only see
// and touch rules in its own namespace. Other rules on the host (system,
// operator-added, or owned by a different caller) stay invisible and untouched.
type Manager interface {
	// ApplyRule installs or updates a rule (idempotent by Rule.ID). Returns
	// ErrInvalidRule for a rule the active backend can't express.
	ApplyRule(ctx context.Context, rule Rule) error
	// RemoveRule removes a rule by ID; a missing rule is a no-op.
	RemoveRule(ctx context.Context, id string) error
	// List returns every rule this Manager owns (namespace-scoped).
	List(ctx context.Context) ([]Rule, error)
	// Namespace returns the namespace this Manager was constructed with.
	Namespace() string
}

// Option is the functional-option type for backend-specific knobs (none today).
type Option func(*base)

// New constructs a Manager for the given backend and namespace, driven by runner.
// Pure: it validates inputs and does not probe the host (use Detect). The zero /
// unimplemented backend is rejected with ErrUnknownBackend, a bad namespace with
// ErrInvalidNamespace, and a nil runner with an error.
//
// namespace must match `^[a-z][a-z0-9_]{0,30}$`. The 31-char cap and the 63-char
// Rule.ID cap together leave room for the separators every backend needs.
func New(b Backend, namespace string, runner exec.Runner, _ ...Option) (Manager, error) {
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}
	if runner == nil {
		return nil, fmt.Errorf("firewall: runner is required")
	}
	fsm, err := newFS(runner)
	if err != nil {
		return nil, err
	}
	base := base{ns: namespace, cmd: cmd{r: runner}, fsm: fsm}
	switch b {
	case Nftables:
		return &nftables{base: base}, nil
	case Firewalld:
		return &firewalld{base: base}, nil
	case UFW:
		return &ufw{base: base}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
}

// lookPath is a package-var seam so Detect is deterministically testable.
var lookPath = osexec.LookPath

// Detect reports the firewall backends usable on THIS host: Nftables when nft is
// on PATH, Firewalld when firewall-cmd is, UFW when ufw is. It lists; it never
// picks and never constructs a Manager. An empty slice means no usable manager.
//
// The ctx is accepted for signature uniformity with the other capability Detect
// functions; the present probe is a pure PATH lookup.
func Detect(ctx context.Context) []Backend {
	_ = ctx
	var out []Backend
	if _, err := lookPath("nft"); err == nil {
		out = append(out, Nftables)
	}
	if _, err := lookPath("firewall-cmd"); err == nil {
		out = append(out, Firewalld)
	}
	if _, err := lookPath("ufw"); err == nil {
		out = append(out, UFW)
	}
	return out
}

// cmd carries the injected Runner and maps a non-zero exit (or a failure to
// execute) into an error — the backends rely on "err != nil ⇒ the tool failed",
// which the old exec.Privileged provided and the new Runner (exit in Result)
// does not.
type cmd struct {
	r exec.Runner
}

func (c cmd) run(ctx context.Context, name string, args ...string) (exec.Result, error) {
	return c.exec(ctx, exec.Command{Name: name, Args: args, Escalate: true})
}

func (c cmd) runStdin(ctx context.Context, stdin, name string, args ...string) (exec.Result, error) {
	return c.exec(ctx, exec.Command{Name: name, Args: args, Stdin: strings.NewReader(stdin), Escalate: true})
}

func (c cmd) exec(ctx context.Context, spec exec.Command) (exec.Result, error) {
	res, err := c.r.Run(ctx, spec)
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		return res, &exec.CommandError{Name: spec.Name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return res, nil
}

// base is embedded by each backend: the namespace, the command runner, and the
// fs.Manager (over the same Runner) the firewalld backend writes service XML
// through.
type base struct {
	ns string
	cmd
	fsm fsManager
}

// Namespace returns the namespace this Manager was constructed with.
func (b base) Namespace() string { return b.ns }
