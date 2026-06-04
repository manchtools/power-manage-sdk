// Package firewall is a cross-backend abstraction for host packet-filter
// management. It follows the SDK's atomic Backend selector convention —
// see sdk/docs/backend-pattern.md for the house style — so the caller
// picks the backend once at startup (typically from agent config) and
// every subsequent ApplyRule / RemoveRule / List call dispatches to the
// chosen implementation.
//
// # Backends
//
// v1 ships three concrete backends and reserves enum slots for two more:
//
//   - BackendNftables (default) — talks to the kernel directly via
//     nft(8). Power-manage owns a dedicated `inet pm_filter` table with
//     an input chain at filter priority 0. Use on hosts where no
//     higher-level firewall manager is active (Debian-without-ufw,
//     Arch, NixOS, minimal base installs).
//
//   - BackendFirewalld — talks to the firewalld daemon via firewall-cmd.
//     firewalld is the authoritative manager on RHEL/Fedora/CentOS
//     Stream; writing raw nft rules behind its back gets blown away on
//     the next reload. Each Rule materialises as a custom service
//     definition pm-<name>.xml in the default zone. v1 scope is narrow:
//     allow-only, concrete tcp/udp, port; no source/dest scoping.
//
//   - BackendUFW — talks to ufw via the ufw(8) CLI. ufw is the standard
//     manager on Debian/Ubuntu desktops and many container hosts.
//     Identity is the rule's native `comment` field, prefixed `pm:`.
//     v1 scope is broader than firewalld: allow + deny, source/dest
//     scoping, and the long-form syntax all round-trip.
//
//   - BackendIptables, BackendPF — reserved enum values, no impl yet.
//     ApplyRule / RemoveRule / List return ErrBackendNotSupported.
//
// # The pm: namespace
//
// Every backend tags rules with a "pm:<name>" identity that round-trips
// through the backend's native annotation field (nftables `comment`,
// firewalld custom-service prefix, ufw `comment`). List filters its
// output by this prefix so the inspection surface is scoped to rules
// power-manage actually owns — operator-added rules, system services,
// distro defaults stay invisible. This is deliberate: a callsite that
// asks "what rules are installed?" should never get back something it
// didn't put there and can't safely mutate.
//
// # Idempotency
//
// Rule.Name is the key every backend uses to find a previously installed
// rule. ApplyRule with an existing Name updates the rule in place
// (delete-then-add inside a single atomic operation where the backend
// supports it). RemoveRule on a missing Name is a no-op — the
// post-condition "this rule is absent" already holds.
//
// Name validation is backend-independent and enforced at the dispatch
// layer: rules must match `^[A-Za-z0-9._-]{1,63}$` so the identity
// survives round-tripping through every backend's annotation field
// without per-backend escaping. Empty names, names with whitespace, or
// names with shell-meta characters return ErrInvalidRule before the
// backend is even consulted.
//
// # Error model
//
// Three sentinels callers branch on:
//
//   - ErrBackendNotSupported — the active backend has no impl for the
//     requested operation. Distinct from a transient failure; callers
//     branch on this to decide whether to skip, retry, or surface a
//     configuration error to the operator.
//
//   - ErrInvalidRule — the Rule struct can't be expressed by the active
//     backend (e.g. a deny rule on firewalld v1, or a port without a
//     concrete protocol on nftables/ufw). The wrapped error message
//     names the offending field so the operator knows what to change.
//
//   - The unwrapped error returned by sysexec.Privileged when the
//     backend's CLI tool fails. Wrap context as needed; do not collapse
//     these into a sentinel — the underlying exit code and stderr are
//     the operator's debugging surface.
//
// # Concurrency
//
// CurrentBackend / SetBackend are atomic; the read path is lock-free.
// The CLI tools each backend calls (nft, firewall-cmd, ufw) are not
// guaranteed reentrant — agents that call ApplyRule from multiple
// goroutines should serialise upstream. The package itself adds no
// locking because the agent runtime already serialises action execution.
//
// # Privilege
//
// Every backend's mutating calls go through sdk/go/sys/exec.Privileged
// so the agent's configured privilege backend (sudo, doas, or
// direct-root) is honoured. The package never shells out directly.
package firewall
