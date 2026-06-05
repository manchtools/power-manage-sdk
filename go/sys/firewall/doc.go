// Package firewall is a cross-backend abstraction for host packet-filter
// management. It is a general-purpose Go library: nothing in the
// package is specific to any one consumer. Callers construct a
// [Manager] with a namespace of their choosing, and every subsequent
// operation is scoped to that namespace.
//
// # Manager + namespace
//
// Identity in this package has two parts: the Manager's namespace and
// each Rule's ID. The namespace is set at construction
// ([New]) and isolates one consumer's rules from every other consumer's
// rules on the host. Two libraries linked into the same Go process,
// each constructing their own Manager with their own namespace, will
// not see each other's rules and cannot accidentally mutate them.
//
//	mgr, err := firewall.New("myapp")
//	if err != nil { ... }
//	mgr.ApplyRule(ctx, firewall.Rule{
//	    ID:       "allow-https",
//	    Allow:    true,
//	    Protocol: firewall.ProtocolTCP,
//	    Port:     443,
//	})
//
// Rule.ID is opaque to the SDK. Pick whatever scheme fits the
// application — a per-rule ULID, a hierarchical path, a UUID, a hash.
// The only constraint is the safe-identifier regex
// (`^[a-z0-9][a-z0-9_-]{0,62}$`) so the value round-trips through every
// backend's native annotation field without per-backend escaping.
//
// Multi-rule actions / batches are first-class: a single caller can
// install N rules under one namespace just by issuing N ApplyRule
// calls with distinct IDs. The SDK does not impose a one-action-one-
// rule constraint.
//
// # Backends
//
// v1 ships three concrete backends and reserves enum slots for two more:
//
//   - [BackendNftables] (default) — talks to the kernel directly via
//     nft(8). Each Manager owns a dedicated `inet <namespace>_filter`
//     table. Use on hosts where no higher-level firewall manager is
//     active (Debian without ufw, Arch, NixOS, minimal base installs).
//
//   - [BackendFirewalld] — talks to the firewalld daemon via
//     firewall-cmd. firewalld is the authoritative manager on
//     RHEL/Fedora/CentOS Stream; writing raw nft rules behind its back
//     gets blown away on the next reload. Each Rule materialises as a
//     custom service `<namespace>-<id>.xml` in the default zone. v1
//     scope is narrow: allow-only, concrete tcp/udp, port — no
//     source/dest scoping.
//
//   - [BackendUFW] — talks to ufw via the ufw(8) CLI. ufw is the
//     standard manager on Debian/Ubuntu desktops and many container
//     hosts. Identity is the rule's native `comment` field, formatted
//     `<namespace>:<id>`. v1 scope is broader than firewalld:
//     allow + deny, source/dest scoping, and the long-form syntax all
//     round-trip.
//
//   - [BackendIptables], [BackendPF] — reserved enum values, no impl
//     yet. ApplyRule / RemoveRule / List return
//     [ErrBackendNotSupported].
//
// Backend selection is host-level — a host runs one active packet-
// filter manager at a time — so the selector is package-level via
// [SetBackend] / [CurrentBackend]. Namespace selection is per-Manager.
//
// # Idempotency
//
// Rule.ID is the key every backend uses to find a previously installed
// rule. [Manager.ApplyRule] with an existing ID updates the rule in
// place (delete-then-add inside a single atomic operation where the
// backend supports it). [Manager.RemoveRule] on a missing ID is a
// no-op — the post-condition "this rule is absent" already holds.
//
// [Manager.List] returns every rule the Manager owns. Rules outside
// the Manager's namespace — system-installed defaults, rules owned by
// a different Manager, operator-added rules — are not returned.
// Inspecting the surface is safe: callers can iterate List output and
// remove or update entries without worrying about clobbering something
// they didn't install.
//
// # Error model
//
// Three sentinels callers branch on:
//
//   - [ErrBackendNotSupported] — the active backend has no impl for the
//     requested operation. Distinct from a transient failure; callers
//     branch on this to decide whether to skip, retry, or surface a
//     configuration error.
//
//   - [ErrInvalidRule] — the Rule struct can't be expressed by the
//     active backend (e.g. a deny rule on firewalld v1, or a port
//     without a concrete protocol on nftables/ufw) or the ID fails
//     validation. The wrapped error message names the offending field.
//
//   - [ErrInvalidNamespace] — the namespace passed to [New] fails
//     validation. Returned only from [New].
//
//   - The unwrapped error returned by sys/exec.Privileged when the
//     backend's CLI tool fails. Wrap context as needed; do not collapse
//     these into a sentinel — the underlying exit code and stderr are
//     the operator's debugging surface.
//
// # Concurrency
//
// [CurrentBackend] / [SetBackend] are atomic; the read path is lock-
// free. A Manager is safe for concurrent use by multiple goroutines,
// but the CLI tools each backend calls (nft, firewall-cmd, ufw) are
// not themselves guaranteed reentrant, so simultaneous mutations from
// many goroutines may serialise inside the OS.
//
// # Privilege
//
// Every backend's mutating calls go through
// sdk/go/sys/exec.Privileged so the consumer's configured privilege
// backend (sudo, doas, or direct-root) is honoured. The package never
// shells out directly.
package firewall
