// Package firewall is a cross-backend abstraction for host packet-filter
// management. It is a general-purpose Go library: nothing in the package is
// specific to any one consumer. Callers construct a [Manager] for an explicit
// backend, a namespace of their choosing, and an injected command [exec.Runner];
// every subsequent operation is scoped to that namespace.
//
// # Manager + namespace
//
// Identity has two parts: the Manager's namespace and each Rule's ID. The
// namespace is set at construction ([New]) and isolates one consumer's rules
// from every other consumer's rules on the host. Two libraries linked into the
// same Go process, each constructing their own Manager with their own namespace,
// will not see each other's rules and cannot accidentally mutate them.
//
//	r, _ := exec.NewRunner(exec.Sudo)
//	mgr, err := firewall.New(firewall.Nftables, "myapp", r)
//	if err != nil { ... }
//	mgr.ApplyRule(ctx, firewall.Rule{
//	    ID:       "allow-https",
//	    Allow:    true,
//	    Protocol: firewall.ProtocolTCP,
//	    Port:     443,
//	})
//
// Rule.ID is opaque to the SDK. Pick whatever scheme fits the application — a
// per-rule ULID, a hierarchical path, a UUID, a hash. The only constraint is the
// safe-identifier regex (`^[a-z0-9][a-z0-9_-]{0,62}$`) so the value round-trips
// through every backend's native annotation field without per-backend escaping.
//
// Multi-rule actions / batches are first-class: a single caller can install N
// rules under one namespace just by issuing N ApplyRule calls with distinct IDs.
//
// # Backends
//
// v1 ships three concrete backends. Pass the chosen one to [New]; [Detect]
// reports which are usable on the current host (it lists, it never picks).
//
//   - [Nftables] — talks to the kernel directly via nft(8). Each Manager owns a
//     dedicated `inet <namespace>_filter` table. Use on hosts where no
//     higher-level firewall manager is active (Debian without ufw, Arch, NixOS,
//     minimal base installs).
//
//   - [Firewalld] — talks to the firewalld daemon via firewall-cmd. firewalld is
//     the authoritative manager on RHEL/Fedora/CentOS Stream; writing raw nft
//     rules behind its back gets blown away on the next reload. Each Rule
//     materialises as a custom service `<namespace>-<id>.xml` in the default
//     zone. v1 scope is narrow: allow-only, concrete tcp/udp, port — no
//     source/dest scoping (an out-of-scope rule returns [ErrInvalidRule]).
//
//   - [UFW] — talks to ufw via the ufw(8) CLI. ufw is the standard manager on
//     Debian/Ubuntu desktops and many container hosts. Identity is the rule's
//     native `comment` field, formatted `<namespace>:<id>`. v1 scope is broader
//     than firewalld: allow + deny, source/dest scoping, and the long-form
//     syntax all round-trip.
//
// Backend selection is explicit per Manager (no process-global selector): the
// caller decides — usually from [Detect] plus its own configuration — and passes
// the value to [New]. The zero value and any unimplemented backend are rejected
// with [ErrUnknownBackend].
//
// # Idempotency
//
// Rule.ID is the key every backend uses to find a previously installed rule.
// [Manager.ApplyRule] with an existing ID updates the rule in place
// (delete-then-add inside a single atomic operation where the backend supports
// it). [Manager.RemoveRule] on a missing ID is a no-op — the post-condition
// "this rule is absent" already holds.
//
// [Manager.List] returns every rule the Manager owns. Rules outside the
// Manager's namespace — system-installed defaults, rules owned by a different
// Manager, operator-added rules — are not returned. Inspecting the surface is
// safe: callers can iterate List output and remove or update entries without
// clobbering something they didn't install.
//
// # Error model
//
// Three sentinels callers branch on:
//
//   - [ErrUnknownBackend] — [New] was given the zero value or a backend the SDK
//     does not implement.
//
//   - [ErrInvalidRule] — the Rule can't be expressed by the active backend (a
//     deny rule on firewalld v1, a port without a concrete protocol on
//     nftables/ufw) or the ID fails validation. The wrapped message names the
//     offending field.
//
//   - [ErrInvalidNamespace] — the namespace passed to [New] fails validation.
//
// [Manager.List] additionally distinguishes absence from emptiness. When the
// namespace was never provisioned (the nftables backend's table does not exist
// yet) List returns a wrapped [io/fs.ErrNotExist], never an empty slice — so a
// caller can never confuse "this namespace has never been set up" with
// "set up, currently holding zero rules". Callers that want absent-treated-as-
// empty opt in explicitly with errors.Is(err, fs.ErrNotExist). A backend whose
// firewall is installed-but-empty (an inactive ufw, an empty firewalld zone)
// returns a nil slice and nil error — that is genuine emptiness, not absence.
//
// When a backend's CLI tool fails for any other reason — escalation denied, the
// tool absent, a crash — the wrapped error carries an exec.CommandError with the
// exit code and stderr. List never reports such a failure as "zero managed
// rules"; it propagates. Do not collapse these into a sentinel.
//
// # Concurrency
//
// A Manager is safe for concurrent use by multiple goroutines, but the CLI tools
// each backend calls (nft, firewall-cmd, ufw) are not themselves guaranteed
// reentrant, so simultaneous mutations from many goroutines may serialise inside
// the OS.
//
// # Privilege
//
// Every backend's mutating calls go through the injected exec.Runner with
// escalation requested, so the consumer's configured privilege backend (sudo,
// doas, or direct-root) is honoured. The package never shells out directly.
package firewall
