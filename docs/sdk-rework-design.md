# SDK Rework — Design Specification

> Status: **Architecture ratified** (Decisions 1–7, §7); testing strategy in §6.
> Per-package contracts
> in §3 are open for line-review. Nothing implemented yet — implementation
> follows §5, starting at the `exec` Runner foundation.
> Goal: make `sdk/go` a library a third-party Go developer can pick up and use
> idiomatically, behaving the way Go developers expect. Supersedes parts of
> [backend-pattern.md](backend-pattern.md) (see Decision 1).

## 0. Scope

**In scope** (the device-side capability surface):
`pkg`, `sys/user`, `sys/service`, `sys/encryption`, `sys/network` (wifi),
`sys/firewall`, `sys/exec`, `sys/fs`, `sys/reboot`, `sys/notify`,
`sys/inventory`, `sys/desktop`, `sys/osquery`, `sys/terminal`, and the planned
`sys/dns` / `sys/netconfig`.

**Out of scope** (shared with the server, already idiomatic, leave alone):
`crypto`, `verify`, `validate`, `logging`, `maintenance`, the streaming
`client.go`, and all `proto`/generated code. **No `.proto` change is required**
— this is a Go-API-only rework.

**Sole consumer:** the agent. Every call site is migrated in the same change
set (per the "security/ergonomics tightening must migrate all callers" rule).
V1, clean break — **no compatibility shims, no deprecation aliases** (delete the
old thing outright).

---

## 1. Conventions (the house style every package adopts)

1. **`ctx context.Context` is the first parameter** of every method that does
   I/O. No package stores a `Context` in a struct (today `pkg` does:
   `NewAptWithContext(ctx)` then `Install(pkgs...)` with no ctx — fixed).
2. **Per-call configuration is an options struct with a documented, valid zero
   value.** Discoverable in godoc, constructed positionally-free. (This is the
   "explicit `defaultUserShell`" instinct.)
3. **Cross-call configuration (a backend, a privilege runner) is carried by a
   handle** built via a constructor. No process-global mutable state.
4. **Multi-implementation capabilities are Go interfaces (the contract)** with
   one unexported concrete type per backend. The constructor takes the backend
   **explicitly** and returns the interface.
5. **Errors are typed, not result-structs.** A `*CommandError` carries
   `ExitCode`/`Stderr` and is inspected via `errors.As`. Sentinels
   (`ErrUnknownBackend`, `ErrBackendUnavailable`, `ErrNotFound`, …) are matched
   via `errors.Is` (see §2 Decision 1 for the two backend sentinels). The
   internal `*exec.Result` never crosses a public boundary.
6. **The SDK owns OS mechanism + OS convention; the agent keeps product
   policy.** The default-shell policy and the `-m`/`-M` "home already exists"
   dance move *into* the SDK; LPS temp-password rows, SSH `authorized_keys`
   splicing, and AccountsService hiding stay *in* the agent.
7. **All existing hardening is preserved behind the new API, never weakened**
   (name validation, `--` positional separation, `SafeReplaceFile`, fd-anchored
   chown/chmod, osquery deny-list, chpasswd newline rejection, PSK-never-in-argv,
   bounded query timeouts).
8. **Godoc-first.** Every package gets a `doc.go` with a runnable `Example`, so
   the SDK's front door is `go doc`, not just the README.

---

## 2. Foundational decisions (these overturn prior choices — please ratify)

### Decision 1 — Retire the global backend singleton (Pattern A → Pattern B everywhere)

`backend-pattern.md` today prescribes a process-wide `atomic.Int32`
(`SetBackend`/`CurrentBackend`) for "one-per-host" capabilities. We replace it
with an exported interface + explicit-backend constructor for **every**
multi-implementation capability:

```go
// BEFORE (Pattern A — global singleton, hidden state):
service.SetServiceBackend(service.ServiceBackendSystemd) // once, at boot
service.EnableNow(ctx, "nginx")                          // reads the hidden global

// AFTER (Pattern B — interface + handle, backend named explicitly):
svc, err := service.New(service.Systemd) // systemd is the only value today
svc.EnableNow(ctx, "nginx")
```

- **Removed:** the global `atomic` selector, `SetBackend`/`CurrentBackend`, and
  every deprecated `SetServiceBackend`/`SetWifiBackend` alias.
- **Why:** global mutable state is the single least-idiomatic thing in the SDK —
  not concurrency-composable, not parallel-testable, spooky-action-at-a-distance.
  An interface handle is what a Go developer reaches for. `backend-pattern.md` is
  rewritten to describe only Pattern B.

#### Backend is always passed explicitly — no default, no stubs

Every backend-pattern package takes its `Backend` **by name in the
constructor**, even when only one backend is implemented today
(`user.New(user.ShadowUtils)`, `service.New(service.Systemd)`):

- **No default / no magic zero value.** There is no `BackendDefault`. The enum's
  zero value is **invalid**; `New` rejects an unset/unknown backend with
  `ErrUnknownBackend` (fail-closed). Valid values start at 1.
- **The enum contains only backends that actually exist** — no speculative
  values, no `ErrUnsupportedBackend` placeholders. Today's
  `ServiceBackendOpenRC`/`Runit`/`S6` (which only ever returned
  `ErrBackendNotSupported`) are **deleted**, not ported.
- **Adding a backend later is additive and safe:** append a new enum value and
  write its implementation. Because every existing call site already *names* its
  backend, none of them silently change behaviour, and there is no "default to
  keep alive" when the second backend appears.
- Backend is never runtime-auto-detected. (`pkg.Detect` stays an explicit,
  separately-named opt-in for callers who *want* OS detection.)
- This applies to the **backend-pattern packages**: `pkg`, `user`, `service`,
  `encryption`, `network`, `firewall`, `dns`, `netconfig`, and `exec` (the
  privilege `Runner`: `exec.NewRunner(exec.Sudo)`). Packages that are
  single-implementation *by nature* (§3.8 — `fs`, `reboot`, `notify`,
  `inventory`, `desktop`, `osquery`, `terminal`) have **no** `Backend` concept
  and take `New(opts...)` only.

#### Availability & discovery — selected-but-unsupported, and "what can this host run?"

Two failure modes are kept distinct, both `errors.Is`-matchable:

```go
// You named a Backend value the SDK does not implement (or the invalid zero
// value). A construction-time, host-independent error.
var ErrUnknownBackend = errors.New("unknown backend")

// You named an IMPLEMENTED backend, but this host lacks its tooling
// (e.g. service.Systemd on an OpenRC box, pkg.Apt on Fedora). The wrapped
// detail names what was missing (binary not on PATH, /run/systemd/system absent).
var ErrBackendUnavailable = errors.New("backend unavailable")
```

**Selected-but-unsupported is fail-closed, never silent.** A handle for an
implemented-but-unavailable backend never executes the wrong tool: the operation
returns `ErrBackendUnavailable`. It is never a panic and never a fallback to a
different backend (that would defeat the explicit-choice rule).

**Discovery is one explicit, read-only function — `Detect`.** It hands the
consumer the backends actually usable on this host; it never picks for them (so
it does not violate `backend-pattern.md`'s "don't auto-detect and pick" rule).
`Supported()`/`Available()` are intentionally **not** separate functions —
"is backend X available?" is `slices.Contains(Detect(ctx), X)`, and "what does
this build implement?" is the enum/godoc — so `Detect` is the whole surface.

```go
// Detect returns the implemented backends whose tooling is usable on THIS host.
// Read-only probe per backend (exec.LookPath / stat of a marker like
// /run/systemd/system); needs no privilege, so it does not go through the
// Runner. Empty slice = this capability has no usable backend on this host.
// Best-effort: a backend that errors on probe is simply omitted.
func Detect(ctx context.Context) []Backend
```

Consumer flow (your model — branch on the count):

```go
switch avail := service.Detect(ctx); len(avail) {
case 0:
    return errors.New("no supported service manager on host")
case 1:
    svc, _ = service.New(avail[0], r) // exactly one → use it
default:
    // caller's own priority among several usable backends:
    svc, _ = service.New(pick(avail), r)
}

// To verify a configured choice instead of letting Detect drive:
if !slices.Contains(service.Detect(ctx), cfg.ServiceBackend) {
    return fmt.Errorf("configured service backend %v not available here", cfg.ServiceBackend)
}
```

**`pkg` is the package where discovery matters most:** the distro's package
manager *must* be probed (a consumer can't know apt vs dnf from config alone), so
`pkg.Detect(ctx)` is the real entry point there. This **replaces** today's
auto-picking `pkg.New()` — `Detect` returns `[]pkg.Backend{pkg.Dnf}` and the
consumer calls `pkg.New(pkg.Dnf)` explicitly. (`sys/network`'s existing
`IsAvailable` collapses into `Detect` too.)

**D6 — probe timing — RESOLVED:** `New` stays **pure** (validates only that the
backend is *known* — no host I/O, no `ctx`; the zero/unknown value →
`ErrUnknownBackend`). The host probe lives solely in `Detect`, which the caller
runs to decide. As a backstop, an operation on a named-but-unavailable backend
fails closed with `ErrBackendUnavailable`. Construction is cheap and total;
discovery is the single explicit `Detect`.

### Decision 2 — Dependency-inject the privilege runner (retire the `exec` global) — **RATIFIED**

`sys/exec` is the foundation every capability uses to escalate. Today the
privilege backend (sudo/doas) is another Pattern-A global. We make it an
injected dependency:

```go
// A Runner abstracts command execution + privilege escalation.
type Runner interface {
    Run(ctx context.Context, c Command) (Result, error)
    Stream(ctx context.Context, c Command, onLine OnLine) (Result, error)
    Backend() PrivilegeBackend // lets fs pick its fd-safe vs sudo path
}

r, _ := exec.NewRunner(exec.Direct)       // agent runs as root; non-root consumer: exec.Sudo / exec.Doas
svc, _ := service.New(service.Systemd, r) // runner is a REQUIRED arg — no default escalation
```

- Every capability constructor takes the `exec.Runner` as a **required
  argument** (`New(backend, runner, opts...)`). **There is no default
  escalation** — a silent `sudo` default would contradict Decision 5's
  "explicit, no magic default". The agent passes `Direct` (it runs as root); a
  non-root consumer passes `Sudo`/`Doas` — from its own config, or by picking
  from `exec.Detect`'s list.
- **Who decides what:** the capability sets `Command.Escalate` per operation
  (Install needs root, Search doesn't); the **Runner** alone knows *how* to
  escalate (`sudo -n`/`doas -n`/bare). `apt install vlc` →
  `runner.Run(Command{Name:"apt-get", Args:[…,"vlc"], Escalate:true})`.
- **Discovery — the same primitive every other interface has.**
  `exec.Detect(ctx) []PrivilegeBackend` **lists** the escalation backends present
  on the host (Sudo/Doas if on PATH) — exactly like `pkg.Detect` / `service.Detect`
  (Decision 6). It lists; it does **not** pick. The consumer reads it, picks one
  explicitly, and passes it down (`exec.NewRunner(picked)`). The SDK never
  auto-picks or auto-constructs a runner (that was the boot-time auto-derive we
  rejected). If the chosen tool is unusable, the first escalated command fails
  closed — `ErrEscalationUnavailable` (not installed) vs `ErrEscalationDenied`
  (`sudo -n` needs a password). Never silent, never a fallback.
- **Sharing is the consumer's job — the SDK ships no global and no facade.** The
  library exposes the `Runner` interface + `NewRunner`; every capability takes a
  runner explicitly. *How* a consumer holds and shares that one runner is its
  composition-root decision (store it on a struct, build a small facade, or — its
  prerogative — its own package var). A global *in the library* is the rejected
  `SetPrivilegeBackend`; a global *in the application* is the app's call and fine.
  This matches idiomatic Go (`*sql.DB`, `*http.Client`, aws-sdk-v2's `aws.Config`)
  — the library hands you a value; you decide how to hold it. (The agent already
  does DI: construct the runner once at boot, store the managers on its
  `Executor` — the runner is never re-threaded.)
- Makes the whole SDK testable with a fake `Runner` — **no more
  `exec.SetPrivilegeBackend` global, no integration container required for unit
  tests of the capability layer.**
- `Result`/`Command`/`Stream` are small public value types owned by `exec`; the
  capability packages return `*exec.CommandError` (Decision 3), never `Result`.

### Decision 3 — Typed errors replace the leaked `*exec.Result`

```go
// CommandError is returned when an underlying OS command fails. It carries the
// captured stderr and exit code so callers can branch on them without importing
// internals. Inspect with errors.As.
type CommandError struct {
    Op       string // e.g. "useradd", "usermod"
    ExitCode int
    Stderr   string
    Err      error
}
func (e *CommandError) Error() string { ... }
func (e *CommandError) Unwrap() error { return e.Err }
```

- `pkg.CommandResult{Success bool, ...}` is removed — `error == nil` is the
  success signal; stdout (when a caller genuinely needs it) is returned
  separately or surfaced through a typed result only where it carries data
  (e.g. `Search`, `List`). The redundant `Success` bool goes away.
- Capability methods return `error` (or `(T, error)` for queries). Callers that
  want stderr do `var ce *exec.CommandError; errors.As(err, &ce)`.

---

## 3. Per-capability contracts

> **The full, audited, line-reviewable contracts now live in
> [sdk-rework-contracts.md](sdk-rework-contracts.md)** — complete method sets,
> options-struct fields, preserved hardening, and the open forks (◇). The
> sketches below remain as a quick overview; the contracts doc is authoritative.

> Notation: only the exported contract is shown. `Option` is the functional-option
> type for backend-specific knobs. **The per-package `New(...)` sketches below omit
> the required `exec.Runner` arg for brevity** — every `New` takes it (see
> Decision 2 / the contracts doc). Each package keeps its concrete backend types
> unexported behind the interface.

### 3.1 `pkg` — package management *(already Pattern B; refine)*

```go
type Manager interface {
    Info(ctx context.Context) (Info, error)
    Install(ctx context.Context, names []string, opts InstallOptions) error
    Remove(ctx context.Context, names []string, opts RemoveOptions) error
    Update(ctx context.Context) error
    Upgrade(ctx context.Context, names []string) error // nil names = upgrade all
    Search(ctx context.Context, query string) ([]SearchResult, error)
    List(ctx context.Context) ([]Package, error)
    ListUpgradable(ctx context.Context) ([]PackageUpdate, error)
    Show(ctx context.Context, name string) (Package, error)
    ListVersions(ctx context.Context, name string) (VersionInfo, error)
    IsInstalled(ctx context.Context, name string) (bool, error)
    InstalledVersion(ctx context.Context, name string) (string, error)
    Pin(ctx context.Context, names []string) error
    Unpin(ctx context.Context, names []string) error
    ListPinned(ctx context.Context) ([]Package, error)
    IsPinned(ctx context.Context, name string) (bool, error)
    Autoremove(ctx context.Context) error // remove orphaned deps; no-op where a backend has none (P1)
    Repair(ctx context.Context) error     // broken-state repair (subsumes apt FixBroken)
    InstalledCount(ctx context.Context) (int, error)
}

type Backend int // Apt, Dnf, Pacman, Zypper, Flatpak
func New(b Backend, opts ...Option) (Manager, error) // explicit backend (runner arg omitted — see note)
func Detect(ctx context.Context) []Backend           // LISTS usable PMs; consumer picks + calls New

type InstallOptions struct { Version string; AllowDowngrade bool }
type RemoveOptions  struct { Purge bool }
```

Changes from today: **ctx-first on every method** (was stored on the
constructor); `Success bool` removed; `InstalledVersion` renamed from
`GetInstalledVersion` (Go: no `Get` prefix); `WithSudo(bool)` replaced by
the required `runner` arg. Per-distro structs (`Apt`, `Dnf`, …) become **unexported**; the
`validating_manager.go` wrapper (WS8 validators) is preserved as the default
decorator returned by `New`.

### 3.2 `sys/user` — user & group management *(NEW interface — your point)*

```go
// Manager is the user/group contract. Linux has several implementations:
// shadow-utils (useradd/usermod/userdel), Debian adduser/deluser,
// systemd-homed (homectl), and busybox adduser.
type Manager interface {
    // Accounts
    Get(ctx context.Context, name string) (Info, error)
    Exists(ctx context.Context, name string) (bool, error)
    Create(ctx context.Context, name string, opts CreateOptions) error
    Modify(ctx context.Context, name string, opts ModifyOptions) error
    Delete(ctx context.Context, name string, opts DeleteOptions) error
    Lock(ctx context.Context, name string) error
    Unlock(ctx context.Context, name string) error
    SetPassword(ctx context.Context, name string, password Secret) error
    ExpirePassword(ctx context.Context, name string) error

    // Groups
    GroupExists(ctx context.Context, name string) (bool, error)
    GroupCreate(ctx context.Context, name string, opts GroupCreateOptions) error
    GroupDelete(ctx context.Context, name string) error
    GroupEnsure(ctx context.Context, name string) error
    AddToGroup(ctx context.Context, name, group string) error
    RemoveFromGroup(ctx context.Context, name, group string) error
}

// Backend is passed explicitly even though shadow-utils is the only value today.
// No default, no zero value: New(ShadowUtils). When adduser/homed/busybox is
// actually written, it's appended here — existing call sites already say
// ShadowUtils, so nothing shifts.
type Backend int
const ShadowUtils Backend = iota + 1 // 1; zero value is invalid → ErrUnknownBackend
func New(b Backend, opts ...Option) (Manager, error)

// CreateOptions: the zero value creates a normal interactive account with a
// login shell and a matching primary group, no home directory.
type CreateOptions struct {
    UID          int    // 0 = auto-assign
    PrimaryGroup string // group name or numeric GID; "" = backend default
    Shell        string // "" = DefaultShell(System) — login shell, or nologin for system accounts
    HomeDir      string // "" = backend default (/home/<name> on shadow-utils)
    Comment      string // GECOS
    System       bool   // system account; also flips DefaultShell to nologin
    CreateHome   bool   // create + populate home, idempotent if it already exists
}
type ModifyOptions      struct { Shell, HomeDir, Comment, PrimaryGroup string } // "" = leave unchanged
type DeleteOptions      struct { RemoveHome bool }
type GroupCreateOptions struct { GID int; System bool }
```

- **The default-shell policy** (`/bin/bash` for interactive, `/usr/sbin/nologin`
  for system/disabled) and the `-m`/`-M` "home already exists" handling move
  here from the agent's [createUser](../../agent/internal/executor/action_user.go).
  The agent's ~170-line `createUser` collapses to: build `CreateOptions` from the
  proto, then compose product policy (temp password + LPS metadata, SSH keys,
  AccountsService hiding) on top of these primitives.
- **Pure helpers stay package-level** (no backend variance): `IsValidName`,
  `GeneratePassword(length int, c Complexity) (Secret, error)` (boolean `complex`
  → a typed `Complexity` enum; returns a `Secret`), `GeneratePassphrase`.
- **Preserved hardening:** `validateName` on every mutating op (no `-`-leading
  name → flag; no newline/colon injection), chpasswd newline/CR rejection,
  bounded query timeouts (now `ctx`-driven with a documented default).
- **v1 exposes one backend: `ShadowUtils`** (today's `useradd`/`usermod`/
  `userdel` behaviour, behind the new `Manager` interface — a pure refactor).
  The `Backend` enum has exactly that one value, **passed explicitly**
  (`user.New(user.ShadowUtils)`); **no `ErrUnsupportedBackend` stubs**. A real
  second backend (adduser/homed/busybox) is appended when actually written.

### 3.3 `sys/service` — init/service manager

```go
type Manager interface {
    Status(ctx context.Context, unit string) (UnitStatus, error)
    IsEnabled(ctx context.Context, unit string) (bool, error)
    IsActive(ctx context.Context, unit string) (bool, error)
    IsMasked(ctx context.Context, unit string) (bool, error)
    Enable(ctx context.Context, unit string) error
    Disable(ctx context.Context, unit string) error
    EnableNow(ctx context.Context, unit string) error
    DisableNow(ctx context.Context, unit string) error
    Start(ctx context.Context, unit string) error
    Stop(ctx context.Context, unit string) error
    Restart(ctx context.Context, unit string) error
    Mask(ctx context.Context, unit string) error
    Unmask(ctx context.Context, unit string) error
    DaemonReload(ctx context.Context) error
    WriteUnit(ctx context.Context, unit, content string) error
    RemoveUnit(ctx context.Context, unit string) error
}
// Backend passed explicitly; Systemd is the only value (OpenRC/Runit/S6 enum
// values, which only ever returned ErrBackendNotSupported, are deleted).
type Backend int
const Systemd Backend = iota + 1
func New(b Backend, opts ...Option) (Manager, error)
func Detect(ctx context.Context) []Backend // probes systemctl + /run/systemd/system
```

- `Status`/`IsEnabled` etc. gain `ctx` (were ctx-less). `ValidateUnitName`
  stays an exported pure helper.

### 3.4 `sys/encryption` — disk encryption

```go
type Manager interface {
    IsEncrypted(ctx context.Context, dev string) (bool, error)
    AddKey(ctx context.Context, dev string, existing, new Secret, opts AddKeyOptions) error
    RemoveKey(ctx context.Context, dev string, key Secret) error
    KillSlot(ctx context.Context, dev string, slot int, existing Secret) error
    VerifyPassphrase(ctx context.Context, dev string, p Secret) (bool, error) // was TestPassphrase (footgun)
    DetectVolume(ctx context.Context) (Volume, error)
    DetectAllVolumes(ctx context.Context) ([]Volume, error)
    TPM() (TPMEnroller, bool) // ok=false when the backend has no TPM support
}
type AddKeyOptions struct { Slot int } // Slot 0 = auto; replaces AddKey/AddKeyToSlot pair
// Backend passed explicitly; LUKS is the only value (GELI/CGD enum values deleted).
type Backend int
const LUKS Backend = iota + 1
func New(b Backend, opts ...Option) (Manager, error)
```

- `TestPassphrase` → `VerifyPassphrase` (the `TestXxx` name is a go-test
  footgun). `AddKey` + `AddKeyToSlot` collapse into one method + `AddKeyOptions`.
  `GeneratePassphrase`/`ValidatePassphrase`/`HashPassphrase` stay pure helpers.
  `ErrInvalidKeySlot` preserved. Passphrases/keys are the shared `exec.Secret`
  (U1), not a bare `string`, so they can't be logged at the call site.

### 3.5 `sys/network` — wifi profiles

```go
type Manager interface {
    ConnectionExists(ctx context.Context, name string) (bool, error)
    Apply(ctx context.Context, p Profile) (changed bool, err error) // was CreateOrUpdate
    Delete(ctx context.Context, name string, opts DeleteOptions) error
    Settings(ctx context.Context, name string) (map[string]string, error)
}
// Backend passed explicitly; NetworkManager (nmcli) is the only value
// (connman/wpa_supplicant/iwd enum values deleted).
type Backend int
const NetworkManager Backend = iota + 1
func New(b Backend, opts ...Option) (Manager, error)
func Detect(ctx context.Context) []Backend // probes nmcli (the old IsAvailable, folded in)
```

- `Profile` (was `WiFiProfile`) is the options struct; its `PSK`/`ClientKey`
  fields are `Secret` (U1). **`BuildAddArgs` / `BuildModifyArgs` /
  `BuildPSKKeyfile` become unexported** (internals leaking today). `IsAvailable`
  folds into `Detect`. The `(bool, error)` from `Apply` keeps the named `changed`
  return. PSK-never-in-argv hardening preserved.

### 3.6 `sys/firewall` — packet filter *(already Pattern B; align naming)*

```go
type Manager interface {
    ApplyRule(ctx context.Context, r Rule) error
    RemoveRule(ctx context.Context, id string) error
    List(ctx context.Context) ([]Rule, error)
    Namespace() string
}
type Backend int // Nftables (default), Firewalld, UFW — the 3 implemented today
func New(b Backend, namespace string, opts ...Option) (Manager, error)
```

- One of the two packages that **keeps a `Backend` selector** (3 real
  implementations). Already a `Manager` with `New(namespace)`; folds the backend
  selection into the constructor (drops the global `SetBackend`) and keeps
  `Rule`, `Protocol`, `ErrInvalidRule`, `ErrInvalidNamespace`. The unimplemented
  `IPTables`/`PF` enum values are deleted (added when actually built).

### 3.7 `sys/dns` & `sys/netconfig` *(planned — define the contract now)*

```go
// dns — systemd-resolved is the only value today; passed explicitly.
type Manager interface {
    Get(ctx context.Context) (Config, error)
    Apply(ctx context.Context, c Config) error
}
type Backend int
const Resolved Backend = iota + 1
func New(b Backend, opts ...Option) (Manager, error)

// netconfig — NetworkManager is the only value today; passed explicitly.
type Manager interface {
    Interfaces(ctx context.Context) ([]Interface, error)
    Apply(ctx context.Context, i Interface) error
}
type Backend int
const NetworkManager Backend = iota + 1
func New(b Backend, opts ...Option) (Manager, error)
```

These move out of `_planned/` into real packages, each exposing only the one
backend it actually implements (resolved / NetworkManager), passed explicitly.
A new enum value is appended if and when a real second implementation is written.

### 3.8 Single-implementation packages — interfaces too (uniformity) — **RATIFIED**

**Decision:** for one-shape-to-learn consistency, these get a `Manager`
interface + `New(...)` constructor like every other package, even though they
have one Linux implementation. They also get the conventions (ctx-first, options
structs, typed errors, no leaked `Result`, the required `runner` arg where they shell out).

**Trade-off acknowledged (the one most likely to draw "YAGNI").** Returning an
interface from `New` for a single concrete impl is mild over-abstraction against
the "accept interfaces, return structs" guideline — and the fake `Runner`
already gives these packages their shell-out testability, so the interface is
buying *uniformity of shape*, not mockability we'd otherwise lack. We take that
cost deliberately: every capability reads `x, _ := pkgname.New(...); x.Method(ctx, …)`,
so a consumer learns one shape, and a future second implementation (should one
ever appear) is additive rather than a breaking constructor change. The cost is
an extra indirection and a type a caller can't down-cast to reach impl-specific
methods — accepted, because the interface *is* the full intended surface.

| Package | Interface (sketch) | Idiomatic fixes |
|---|---|---|
| `sys/fs` | `Manager`: ReadFile / WriteFile / Mkdir / Remove / RemoveDir / Copy / SetOwnership… | **F1**: one `WriteFile`+`WriteOptions` (always atomic + symlink-safe, `os.FileMode`) replaces the 4 write variants; stop returning `*exec.Result`; keep fd-anchored ops + deny-by-default verbatim |
| `sys/reboot` | `Manager`: IsRequired / Schedule / Cancel | `Schedule(ctx, ScheduleOptions{Delay, Message})`; multi-distro detection stays internal (not an operator-picked backend) |
| `sys/notify` | `Manager`: NotifyAll / NotifyUsers | both **must return `error`** (today they swallow) |
| `sys/inventory` | `Collector`: SystemInfo / OSInfo / Disks / NetworkInterfaces | ctx-first; consistent typed structs |
| `sys/desktop` | `Manager`: ActiveSessions / HomeUsers / RunAsCommand | ctx-first; `Session` value type stays |
| `sys/osquery` | `Querier`: Query / QueryTable | keep the lazy-init + the **credential-table deny-list** verbatim; ctx-first (already a handle — add the interface) |
| `sys/terminal` | `Manager`: Open / Resize / Close | ctx-first (already a handle — add the interface) |

> Note: these are single-implementation **by nature** — there is no second way to
> read `/proc` or replace a file, so they have no `Backend` concept at all (unlike
> `service`/`user`, which name their one backend explicitly against a future
> second). Their constructor is `New(runner, opts...)` — no `Backend` argument,
> but still the required `exec.Runner` so the construction shape matches.
>
> **One exception: `terminal`.** A PTY session is a long-lived, bidirectional
> stream, not a captured one-shot `Command` → `Result`, so the Runner abstraction
> cannot model it. `terminal.New()` therefore takes **no** Runner; honesty (no
> dead parameter) wins over shape-uniformity here. The privilege to switch UID
> comes from the agent already running as root (the child's `syscall.Credential`).
> `osquery` and `desktop` do take the Runner — osquery runs every query through
> it; desktop runs its `loginctl` probes through it (and gains the forced-C locale
> for stable stderr parsing), while `RunAsCommand` builds a direct `*exec.Cmd`
> that intentionally keeps the *user's* locale.

---

## 4. Onboarding ergonomics (so a consumer "can just start using it")

```go
// One runner, chosen EXPLICITLY by the consumer from its own config (no SDK
// detection). The consumer holds it however it likes — the SDK ships no global
// and no facade.
r, _ := exec.NewRunner(cfg.Escalation) // e.g. exec.Direct for the root agent; Sudo/Doas elsewhere

svc, _ := service.New(service.Systemd, r)
_ = svc.EnableNow(ctx, "nginx.service")

um, _ := user.New(user.ShadowUtils, r)
_ = um.Create(ctx, "deploy", user.CreateOptions{CreateHome: true})

// Tests swap that one arg — no container, no sudo, no global to save/restore:
um, _ = user.New(user.ShadowUtils, exectest.NewRunner())
```

- A `doc.go` + runnable `Example` per package.
- A top-level `sdk/go/README` "Quick start" showing the construct-a-handle flow.
- Sentinels and `*CommandError` documented as the inspection contract.

---

## 5. Migration plan (design-all-now → implement)

1. **Ratify this doc** (Decisions 1–7, the §6 testing strategy, and §3.8).
2. **`exec` Runner first** (foundation) — sdk PR: introduce `Runner`,
   `Command`, `Result`, `CommandError`, `Secret`, `Detect`, and
   `exectest.FakeRunner`; keep `--` separation + SIGKILL escalation + output cap.
   Agent: construct one runner at boot — **no default escalation, the consumer
   picks** (from config or `exec.Detect`).
3. **Capability packages, one PR each**, in dependency order
   (`user`, `service`, `encryption`, `network`, `firewall`, `pkg`,
   then `dns`/`netconfig`), each: **first snapshot the current agent's argv as
   golden fixtures** (§6 tier 3 — captured from the *unmodified* agent, in the
   RED commit, before the builder moves) + new interface + backends + options +
   typed errors + `doc.go`/examples + **full agent call-site migration in the
   same PR** + tests (correct / absent / present-but-wrong per the TDD rule).
4. **Single-impl cleanups** (`fs`, `reboot`, `notify`, `inventory`, `desktop`,
   `osquery`, `terminal`) — batched.
5. **Rewrite `backend-pattern.md`** to describe only Pattern B; delete Pattern A.
6. Each sdk PR → bump agent pin → agent PR. Branch-per-issue on both repos.

Cross-repo order per change: **sdk → agent**. No proto, so web is untouched.

### Behavioral signature changes the agent must absorb (migration risk register)

These are not pure renames — the *contract* changes, so the agent call sites
need real review (not a mechanical find-replace) in the same PR that lands each:

- **`pkg` loses auto-pick.** Today's auto-detecting `pkg.New()` is replaced by
  `pkg.Detect(ctx)` → explicit `pkg.New(picked, runner)`. The agent's boot/config
  must now *make and hold* the package-manager choice (it can drive it from
  `Detect` when config doesn't pin one). Failure mode shifts from "silently
  picked the wrong PM" to a fail-closed `ErrBackendUnavailable`.
- **`reboot.IsRequired()` → `(bool, error)`.** It no longer swallows a probe
  failure; the agent must decide what a failed probe means (assume-no vs surface).
- **`notify.NotifyAll`/`NotifyUsers` now return `error`.** Were fire-and-forget;
  the agent now chooses explicitly to log-and-ignore best-effort failures.
- **No method returns `*exec.Result` anymore.** Call sites that branched on
  `Result.ExitCode`/`Stderr` (e.g. "user already exists", cryptsetup wrong-
  passphrase) must switch to `errors.As(err, &ce)` on `*exec.CommandError`, or
  read the typed query result — verify each such branch, don't assume.
- **Default escalation is gone.** Every `New` requires a `Runner`; the agent
  constructs exactly one `exec.Direct` runner at boot (it runs as root) and
  threads it. A missing/incorrect runner is now a construction-site error, not a
  silent `sudo`.

---

## 6. Testing strategy & TDD

**Red-before-green, every package.** For each capability the failing tests are
written *first*, run, and confirmed RED for the right reason, then the
implementation makes them green — never the reverse. A correct-behaviour test
that fails is treated as a finding (usually in the code). No `t.Skip`/build-tag
to make a suite green.

### The keystone: a shipped fake `Runner`

Step 1 ships `sdk/go/sys/exec/exectest` alongside the real `Runner`:

```go
// FakeRunner records every Command and returns scripted Results, so a capability
// Manager can be unit-tested with no host, no sudo, no container.
type FakeRunner struct { Backend exec.PrivilegeBackend }
func (f *FakeRunner) Calls() []exec.Command            // every Command it received, in order
func (f *FakeRunner) Push(r exec.Result, err error)    // script the next Run/Stream outcome
```

Because every capability handle is built with an explicit runner — pass a fake — the
flag-assembly logic that moves out of the agent (e.g. `user.Create`'s
`useradd` flags + default-shell policy) is now unit-testable directly.

### Three tiers — unit is ADDITIVE, real-system integration is the source of truth

**Non-regression rule:** the existing real-system coverage is *preserved in full
and extended*, never replaced. Every `*_Integration` test that runs today against
a real tool (apt/dnf/pacman/zypper install-remove-upgrade cycles, real
`cryptsetup` key add/remove/verify, real `useradd`/`usermod`/`userdel`, real
`systemctl enable/disable`, real `nft`/`ufw`/`firewalld` apply-list-remove cycles)
is **ported to the new API and kept green**. The fake Runner adds a *new, faster*
logic tier on top — it does **not** remove a single real-system test. A method
is not considered covered by unit tests alone.

1. **Real-system integration — the source of truth for "it actually works."**
   Runs in the real harnesses we already have: `sdk/test/run-tests.sh` (systemd +
   non-root sudo container) for `sys/*`, and the per-distro package-manager
   containers for `pkg`. Every capability keeps end-to-end coverage against the
   **real** tool through the **real** Runner: the command is built, escalated, run,
   and its side effect verified (the user exists, the slot is added, the unit is
   enabled, the package is installed, the rule is in the table).
   - **The Runner gets first-class, thorough real-system tests** — it is the new
     single chokepoint, so it earns the most: `Sudo`/`Doas` actually escalate
     (do something only root can), `Direct` runs unwrapped, the env blocklist
     actually keeps `LD_PRELOAD` out of the child, SIGTERM→SIGKILL actually reaps
     a **trap-ignoring loop** (a bare `sleep` dies on group SIGTERM → green for the
     wrong reason — use the WS16 loop), the 1 MiB cap actually truncates, `--`
     actually blocks flag injection, `Stream` delivers real streaming output.
   - The privilege-keyed `fs` paths run on real systems **both** ways — the
     `Direct` (fd-safe `O_NOFOLLOW`/`renameat2`) path *and* the sudo path — since
     they are different code (the WS6 lesson: unconditional fd broke the non-root
     sudo integration CI).
2. **Unit (fake Runner) — additive fast tier, runs under `go test -race ./...`,
   no container.** Catches logic/validation/error-mapping bugs in milliseconds so
   the slow real-system tier isn't the only net. For every method, the matrix
   from the TDD rule — **correct / absent / present-but-wrong** — plus error
   mapping and hardening pins:
   - *Correct:* valid options → the exact `Command` is built (name, `--`
     separation, flags, order); a success `Result` → `nil` error.
   - *Absent:* missing required field (empty username, zero `Backend`) → rejected
     **before** the Runner is called (`len(fake.Calls()) == 0`).
   - *Present-but-wrong:* malformed input — leading-`-` name, newline in a
     `Secret`, out-of-range keyslot, bad unit name, `http://` repo URL — rejected,
     Runner never called. ("Wrong" derived from design intent, not from the
     validator under test.)
   - *Error mapping:* Runner returns `ExitCode != 0` + `Stderr` → `*exec.CommandError`.
   - *Hardening pins:* osquery deny-list short-circuits before any call;
     **`Secret`/PSK never appears in any recorded `Command.Args`**; `Secret.String()`
     is `"[REDACTED]"`. (The symlink-refusal / TOCTOU pins run in tier 1 — they
     need a real filesystem to be meaningful.)
3. **Characterization / parity (golden) — bridges the two, pins the refactor.**
   A table asserts the new `Manager` builds the **byte-identical argv** today's
   agent builds (golden values) — so the *preserved* real-system tests still apply
   to the refactored code, and behaviour can't silently drift. Critical for
   `user.Create` / `service` / `pkg`, where flag assembly moves between repos.
   Part of the RED suite — fails until the new code reproduces the old command.
   - **Capture the goldens from the CURRENT agent FIRST — before touching the
     code.** The golden corpus is the exact argv today's `createUser` /
     service / `pkg` paths emit, extracted from the unmodified agent (e.g. by
     running the existing agent tests with a recording runner, or lifting the
     literals the current builders produce). Freezing them *before* the refactor
     is what makes the parity test meaningful: per the TDD rule, the expected
     value must come from the pre-existing behaviour, **never derived from the
     new builder under test** — a golden generated from the refactored code
     proves only that the code equals itself. So step (1) of every capability PR
     that moves flag assembly is "snapshot the current argv as fixtures," and
     that snapshot is committed in the RED commit.

### Fitness functions (lock the architecture)

Self-discovering archtest guards, run under `go test`:
- **No global backend state survives** — discover every `sys/*` + `pkg` package
  by directory and fail if any exports a `Set*Backend`/`Current*Backend` or a
  package-level backend selector var. Matches-zero guard so an empty discovery
  set fails too. Locks Decision 1 against regression.
- **Every `New(Backend, …)` rejects the zero/unknown value** with
  `ErrUnknownBackend` — discovered across the backend-pattern packages.
- **`Secret.Reveal()` is called only from the known credential sinks.** The
  redacted `String()` + `Reveal()`-single-sink discipline (U1) only holds if
  `Reveal()` can't leak through a log/format path. An AST guard discovers every
  `.Reveal()` call site across `sys/*` + `pkg` and fails on any outside an
  allowlist of the genuine sinks (the chpasswd/cryptsetup stdin writer, the PSK
  keyfile writer, …). Allowlist entries are by call-site role, and a no-stale
  guard fails if an allowlisted sink no longer calls `Reveal()`; a matches-zero
  guard fails if the walk finds no `Reveal()` calls at all (the discovery went
  dead). This is the fitness-function complement to the unit-tier pin that a
  `Secret` never appears in a recorded `Command.Args`.

### CI wiring & per-PR flow

- Every PR: `go test -race ./...` (unit + parity + fitness, no container) + the
  integration-container job. CR review before push; poll CI green.
- Per capability PR: (1) write the failing tests — unit (fake Runner) + parity
  golden **+ the ported/extended real-system integration tests** → (2) confirm
  RED → (3) implement → (4) green (unit locally; the integration job proves it on
  a real host) → (5) **migrate the agent call sites in the same PR and run the
  agent suite** (the agent's own unit + integration tests are the safety net that
  behaviour didn't drift) → (6) CR, merge. The clean-break (sdk+agent together)
  means main is never left half-migrated.
- **A capability PR does not merge on green unit tests alone** — its real-system
  integration job must be green too. Run the SDK integration harness
  (`sdk/test/run-tests.sh` + per-distro `pkg` containers) locally/CI before merge,
  same as today.

## 7. Decision log

1. **Decision 1** — interface + explicit-backend constructor everywhere; retire
   the global singleton. **RATIFIED** (rewrites `backend-pattern.md`).
2. **Decision 2** — inject a `Runner`, retire `exec.SetPrivilegeBackend`.
   **RATIFIED.**
3. **§3.8** — single-implementation packages also become interfaces for
   uniformity. **RATIFIED.**
4. **`user` backends for v1** — implement one backend (`ShadowUtils`) behind the
   `Manager` interface (pure refactor of today's `useradd`/`usermod`/`userdel`).
   No `ErrUnsupportedBackend` placeholders. **RATIFIED.**
5. **Backend is always passed explicitly; no default; expose only implemented
   backends** — every backend-pattern package takes its `Backend` by name in the
   constructor, even single-backend ones (`user.New(user.ShadowUtils)`). The
   enum's zero value is invalid (`New` → `ErrUnknownBackend`, fail-closed); valid
   values start at 1; the enum contains only built backends (speculative values
   deleted, not stubbed). Adding a backend later is additive — existing call
   sites already name theirs, so there is no default to keep alive. Packages that
   are single-implementation *by nature* (§3.8) have no `Backend` at all.
   **RATIFIED.**
6. **Availability & discovery** — two sentinels: `ErrUnknownBackend`
   (unimplemented/zero value, at `New`) and `ErrBackendUnavailable` (implemented
   but host lacks tooling, fail-closed at use). Discovery is a single
   `Detect(ctx) []Backend` per backend-pattern package (no separate
   `Supported`/`Available`). `New` is **pure** (no probe, no `ctx`); the caller
   runs `Detect` and branches on the count. A named-but-unavailable backend never
   silently falls back. **RATIFIED.**
7. **Runner: explicit, discoverable like everything else, no library global, no
   library facade.** The `exec.Runner` is a **required** arg on every `New` (no
   default escalation). `exec.Detect(ctx) []PrivilegeBackend` **lists** the
   available escalation backends (Sudo/Doas on PATH) — the *same* `Detect`
   primitive as capability backends (Decision 6); it lists, the consumer **picks
   explicitly** and passes the runner down. The SDK never auto-picks/auto-constructs
   a runner (no `DetectRunner`; the rejected boot-time auto-derive). **How the
   runner is shared is the consumer's composition-root decision**; the SDK ships
   neither a global nor a `System` facade (a library global = the rejected
   `SetPrivilegeBackend`; an app-level global is the app's prerogative). Layering:
   capability sets `Command.Escalate` per op; the Runner alone applies
   sudo/doas/bare. Fail-closed: `ErrEscalationUnavailable` / `ErrEscalationDenied`.
   **RATIFIED.**
