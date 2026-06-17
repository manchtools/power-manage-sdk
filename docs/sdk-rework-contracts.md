# SDK Rework — Refined Per-Package Contracts

> Companion to [sdk-rework-design.md](sdk-rework-design.md). That doc holds the
> ratified architecture (Decisions 1–7); this one is the **line-reviewable API
> surface** for every in-scope package, derived from a full source audit. Each
> section lists the interface, options, errors, preserved hardening, and what
> changes. All forks (U1/O1/F1/P1) are **resolved** — see §14.

Conventions (from the design doc): ctx-first; options structs with valid zero
values; typed errors (`*exec.CommandError` + sentinels); interface + explicit
`Backend`; **the `exec.Runner` is passed explicitly as a required constructor
argument** — `New(backend, runner, opts...)` for backend-pattern packages,
`New(runner, opts...)` for single-impl — there is **no default escalation** (a
silent `sudo` default would contradict Decision 5). `Detect(ctx) []Backend` is
the sole discovery primitive; no global state; no leaked `*exec.Result`. The
per-package `New(...)` signatures below omit the required `runner` arg for
brevity.

---

## 0. `exec` — the Runner foundation (implement first)

The ~12 current entrypoints (`Run`, `RunInDir`, `RunWithStdin`, `RunWithCLocale`,
`RunStreaming`, `RunStreamingChildPath`, `Privileged`, `PrivilegedWithStdin`,
`PrivilegedStreaming`, `Query*`, `Check*`) collapse into **one `Command` value +
two methods**:

```go
type PrivilegeBackend int
const (
    Sudo   PrivilegeBackend = iota + 1 // sudo -n
    Doas                               // doas -n
    Direct                             // no wrapper — process is already root
)

// Command describes one execution. Zero value invalid (Name required).
type Command struct {
    Name      string    // resolved to an absolute path before escalation
    Args      []string
    Dir       string    // "" = inherit cwd
    Env       []string  // extra KEY=VALUE; screened by the env blocklist
    Stdin     io.Reader
    CLocale   bool      // force LC_ALL=C / LANG=C for stable parsing
    ChildPath string    // explicit child PATH (per-user runuser); "" = sanitized default
    Escalate  bool      // run through the privilege backend
}

type Result struct { ExitCode int; Stdout, Stderr string }

// CommandError is returned by the capability layer when a command exits
// non-zero. Inspect with errors.As. (The Runner itself does NOT treat a
// non-zero exit as an error — see below.)
type CommandError struct { Name string; ExitCode int; Stderr string; Err error }
func (e *CommandError) Error() string ; func (e *CommandError) Unwrap() error

type Stream int
const ( StdoutStream Stream = iota + 1; StderrStream )
type OnLine func(s Stream, line string, seq int64)

type Runner interface {
    Run(ctx context.Context, c Command) (Result, error)
    Stream(ctx context.Context, c Command, onLine OnLine) (Result, error)
    Backend() PrivilegeBackend // lets fs pick its fd-safe vs sudo path
}
func NewRunner(b PrivilegeBackend) (Runner, error) // pure: validates b is known; does NOT probe the host

// Detect — the SAME discovery primitive every capability backend has (Decision 6):
// it LISTS the escalation backends available on this host (Sudo if `sudo` on PATH,
// Doas if `doas` on PATH). It does NOT pick and does NOT construct anything. The
// consumer reads the list, picks one explicitly, and passes it down. There is no
// DetectRunner / auto-pick-and-construct (that was the boot-time auto-derive we
// rejected). Direct — run as the current process, no wrapper — needs no detection.
func Detect(ctx context.Context) []PrivilegeBackend
//   avail := exec.Detect(ctx)               // e.g. []PrivilegeBackend{exec.Sudo}
//   runner, _ := exec.NewRunner(pick(avail)) // consumer picks; pass it to every New(...)

// If the chosen tool turns out unusable, the FIRST escalated command fails closed:
var ErrEscalationUnavailable error // chosen tool (sudo/doas) not installed
var ErrEscalationDenied      error // `sudo -n`/`doas -n` needs a password (no NOPASSWD)

// Pure, still package-level:
const EndOfOptions = "--"
const MaxOutputBytes = 1 << 20
func SeparatePositionals(flags []string, positionals ...string) []string
var ErrInvalidEnvVar, ErrBlockedEnvVar error
```

- **Runner error semantics:** `Run`/`Stream` return a non-nil `error` only on
  *failure to execute* (binary not found, ctx cancelled, blocked env var). A
  **non-zero exit is reported in `Result.ExitCode`, not as an error** — because
  several callers branch on specific codes (`cryptsetup` 2 = wrong passphrase,
  `isLuks` 1 = not LUKS, `pkill` 1 = no match). The **capability layer** decides
  when a non-zero exit becomes a `*CommandError`. Clean split: Runner = mechanism,
  Manager = policy.
- **Preserved verbatim:** the env blocklist (`LD_PRELOAD`/`PATH`/`BASH_ENV`/…),
  `--` positional separation, 1 MiB per-stream output cap + `[output truncated]`,
  SIGTERM→SIGKILL process-group escalation after `killGrace`, absolute-path
  resolution before escalation, `CappedBuffer`'s always-consume write contract.
- **Deleted:** `SetPrivilegeBackend`/`CurrentPrivilegeBackend` globals; the
  deprecated `Query`/`QueryOutput`/`Check` (caller does `Run` + reads `Result`).
- **Escalation layering (who decides what):** a capability backend sets
  `Command.Escalate` per operation ("this needs privilege" — e.g. `pkg.Install`
  yes, `pkg.Search` no) and builds the argv; it is **escalation-method-agnostic**.
  The **Runner** is the only component that knows *how* to escalate — `Sudo` →
  `sudo -n <abs-path> …`, `Doas` → `doas -n …`, `Direct` → bare. The
  `PrivilegeBackend` is chosen **once**, explicitly, where the Runner is
  constructed (the agent runs as root → `Direct`, no wrapper; a non-root SDK
  consumer picks `Sudo`/`Doas` explicitly — from its own config or from
  `exec.Detect`'s list; the SDK never picks for it). So
  `apt install vlc` = `runner.Run(Command{Name:"apt-get", Args:[…,"vlc"],
  Escalate:true})`; the `sudo`/`doas`/nothing prefix is entirely the Runner's job.

---

## 1. `pkg`

```go
type Backend int
const ( Apt Backend = iota + 1; Dnf; Pacman; Zypper; Flatpak )

type Manager interface {
    Info(ctx context.Context) (Info, error)
    Install(ctx context.Context, names []string, opts InstallOptions) error
    Remove(ctx context.Context, names []string, opts RemoveOptions) error
    Update(ctx context.Context) error
    Upgrade(ctx context.Context, names []string) error // nil = all
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
    Autoremove(ctx context.Context) error // remove orphaned deps; no-op where a backend has no equivalent
    Repair(ctx context.Context) error     // broken-state repair (subsumes apt FixBroken)
    InstalledCount(ctx context.Context) (int, error)
}
func New(b Backend, opts ...Option) (Manager, error)
func Detect(ctx context.Context) []Backend // probes apt-get/dnf/pacman/zypper/flatpak on PATH

type InstallOptions struct { Version string; AllowDowngrade bool }
type RemoveOptions  struct { Purge bool } // folds the per-backend Purge methods in
```

- **ctx moves to every method** (was stored on the constructor via
  `NewAptWithContext`). `Success bool` dropped from results (`error` is the
  signal). `GetInstalledVersion`→`InstalledVersion` (no `Get` prefix). `WithSudo`
  → the required `runner` arg. Per-distro structs (`Apt`/`Dnf`/…) **unexported**.
- **Validation always-on:** `New` returns the validating manager (the
  `WithValidation` wrapper becomes the default, not opt-in). All validators
  preserved: `ValidatePackageName`/`Names`/`Version`, `ValidateRpmPackageName`,
  `ValidateRemoteName`, `ValidateRepoBaseURL` (https-only), `ValidateGpgKeyRef`
  (no `..`, no plaintext http, no `ext::`). LANG=C/LC_ALL=C read-side env preserved.
- `InstallVersion` folds into `Install(names, InstallOptions{Version})`; the
  per-backend version syntax (`name=version` vs `name-version`) stays internal.
- **P1 — RESOLVED (generalize or fold; no typed-assertion side-interface).**
  `Autoremove(ctx) error` is a first-class method — generic across
  apt/dnf/pacman/flatpak; a backend with no native equivalent **no-ops**
  (returns nil). `DistUpgrade` **folds into `Upgrade(ctx, nil)`** (apt runs
  `dist-upgrade` internally for held-back packages; dnf/pacman/flatpak's
  upgrade-all is already full). `FixBroken` **folds into `Repair(ctx)`**. No
  apt-only interface.

---

## 2. `user`

```go
const ShadowUtils Backend = iota + 1 // only value today (Decision 5)
func New(b Backend, opts ...Option) (Manager, error)

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
    PrimaryGroup(ctx context.Context, name string) (string, error)
    SupplementaryGroups(ctx context.Context, name string) ([]string, error)
    KillSessions(ctx context.Context, name string) error
    SetHiddenOnLoginScreen(ctx context.Context, name string, hidden bool) error
    // Groups
    GroupExists(ctx context.Context, name string) (bool, error)
    GroupMembers(ctx context.Context, name string) ([]string, error)
    GroupCreate(ctx context.Context, name string, opts GroupCreateOptions) error
    GroupDelete(ctx context.Context, name string) error
    GroupEnsure(ctx context.Context, name string) error
    AddToGroup(ctx context.Context, name, group string) error
    RemoveFromGroup(ctx context.Context, name, group string) error
}

// CreateOptions zero value = normal interactive account, login shell, matching
// primary group, no home.
type CreateOptions struct {
    UID          int      // 0 = auto
    PrimaryGroup string   // name or numeric GID; "" = useradd matching-group default
    Groups       []string // supplementary
    Shell        string   // "" = DefaultShell(System): login shell, nologin if System
    HomeDir      string   // "" = /home/<name>
    Comment      string   // GECOS
    System       bool     // -r; flips DefaultShell to nologin
    CreateHome   bool     // -m; SDK handles the "home already exists" -M/chown dance
}
type ModifyOptions      struct { Shell, HomeDir, Comment, PrimaryGroup string } // "" = unchanged
type DeleteOptions      struct { RemoveHome bool }
type GroupCreateOptions struct { GID int; System bool }

// Pure helpers stay package-level (no backend variance):
func IsValidName(name string) bool
func DefaultShell(system bool) string          // "/bin/bash" | "/usr/sbin/nologin"
func GeneratePassword(length int, c Complexity) (Secret, error) // was complex bool
```

- **The agent's 170-line `createUser` flag-assembly + default-shell policy +
  `-m`/`-M` home dance move INTO `Create`.** The agent then composes product
  policy (LPS temp-password rows, SSH `authorized_keys`, AccountsService hiding)
  on top.
- `Get`/`Exists`/`PrimaryGroup`/group queries gain `ctx` (the internal 10s
  `queryTimeout` becomes the default when the ctx has no deadline). **No more
  `(*exec.Result, error)`** anywhere — non-zero `useradd`/`usermod` exit →
  `*exec.CommandError` carrying stderr (the "user already exists" context callers
  need). `ChownRecursive` deprecated alias **deleted** (use `fs`).
- **Preserved:** `IsValidName`/`validateName` on every mutation (no `-`-leading →
  flag; no newline/colon injection), `SetPassword` newline/CR rejection.
- **U1 — `Secret` type — RATIFIED (yes).** Passwords/keys are an `exec.Secret`
  wrapper (redacted `String()`, `Reveal()` for the one sink, newline-rejecting
  constructor), not bare `string`. Applies here + encryption + network PSK. §14.

---

## 3. `service`

```go
const Systemd Backend = iota + 1 // only value (OpenRC/Runit/S6 enum deleted)
func New(b Backend, opts ...Option) (Manager, error)
func Detect(ctx context.Context) []Backend // probes systemctl + /run/systemd/system

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
type UnitStatus struct { Enabled, Active, Masked, Static bool }
func ValidateUnitName(unit string) error // pure helper
```

- `Status`/`IsEnabled`/`IsActive`/`IsMasked` gain `ctx` (the 30s
  `systemctlQueryTimeout` becomes the no-deadline default). Global
  `SetBackend`/`SetServiceBackend` + aliases deleted.
- **Preserved:** `validSystemdUnitName` regex, the `validSystemctlOutputs`
  whitelist (distinguishes "disabled" from "couldn't tell"), `--` on every
  `systemctl` call, `WriteUnit` via `fs` atomic write.

---

## 4. `encryption`

```go
const LUKS Backend = iota + 1 // only value (GELI/CGD enum deleted)
func New(b Backend, opts ...Option) (Manager, error)

type Manager interface {
    IsEncrypted(ctx context.Context, dev string) (bool, error)      // was IsLuks
    AddKey(ctx context.Context, dev string, existing, new Secret, opts AddKeyOptions) error
    RemoveKey(ctx context.Context, dev string, key Secret) error
    KillSlot(ctx context.Context, dev string, slot int, existing Secret) error
    VerifyPassphrase(ctx context.Context, dev string, p Secret) (bool, error) // was TestPassphrase
    DetectVolume(ctx context.Context) (Volume, error)
    DetectVolumeByKey(ctx context.Context, p Secret) (Volume, error)
    DetectAllVolumes(ctx context.Context) ([]Volume, error)
    TPM() (TPMEnroller, bool) // ok=false if backend has no TPM support
}
type AddKeyOptions struct { Slot int } // 0 = auto; folds AddKey + AddKeyToSlot
type Volume struct { DevicePath, MapperName, MountPoint string }
type TPMEnroller interface {
    Available(ctx context.Context) (bool, error)        // was HasTPM2
    Enroll(ctx context.Context, dev string, existing Secret) error
    Wipe(ctx context.Context, dev string, existing Secret) error
}
const ( LuksMinKeySlot = 0; LuksMaxKeySlot = 7 )
var ErrInvalidKeySlot error

// Pure helpers stay package-level:
func GeneratePassphrase(minWords int) (Secret, error)
func ValidatePassphrase(p string, minLength int, c Complexity) string
func HashPassphrase(p string) string ; func IsRecentlyUsed(p string, hashes []string) bool
type Complexity int ; const ( ComplexityNone Complexity = iota; ComplexityAlphanumeric; ComplexityComplex )
```

- **`TestPassphrase`→`VerifyPassphrase`** (the `TestXxx` non-test name is a
  go-test footgun). `AddKey`+`AddKeyToSlot` collapse to one method + options.
  `requireBackend`/global `SetBackend` deleted (the handle is LUKS by
  construction). `HasTPM2`→`TPMEnroller.Available`.
- **Preserved:** keyslot 0–7 validation, ephemeral key files in `/dev/shm`
  (mode 0600, never disk), zero-overwrite + `O_NOFOLLOW` cleanup,
  `cryptsetup` exit-code translation, the `lsblk -J` LUKS/LVM-on-LUKS detection.

---

## 5. `network` (wifi)

```go
const NetworkManager Backend = iota + 1 // only value (connman/wpa/iwd deleted)
func New(b Backend, opts ...Option) (Manager, error)
func Detect(ctx context.Context) []Backend // probes nmcli

type Manager interface {
    ConnectionExists(ctx context.Context, name string) (bool, error)
    Apply(ctx context.Context, p Profile) (changed bool, err error) // was CreateOrUpdate
    Delete(ctx context.Context, name string, opts DeleteOptions) error
    Settings(ctx context.Context, name string) (map[string]string, error)
}
type AuthType int ; const ( AuthPSK AuthType = iota + 1; AuthEAPTLS )
type Profile struct {
    Name, SSID string
    AuthType   AuthType
    PSK        Secret // PSK only — never enters argv (keyfile route preserved)
    CACert, ClientCert string
    ClientKey  Secret  // EAP-TLS
    Identity   string
    AutoConnect, Hidden bool
    Priority   int
    CertDir    string // must be under CertBaseDir
}
type DeleteOptions struct { CertDir string }
const CertBaseDir = "/var/lib/power-manage/wifi"
```

- `IsAvailable` folds into `Detect`. **`BuildAddArgs`/`BuildModifyArgs`/
  `BuildPSKKeyfile` become unexported** (they were leaking internals). `Apply`
  keeps the named `changed bool` return.
- **Preserved:** PSK-never-in-argv (keyfile mode 0600 + reload), EAP-TLS staged
  cert swap with rollback, `CertDir`-under-`CertBaseDir` symlink-aware validation.

---

## 6. `firewall`

```go
const ( Nftables Backend = iota + 1; Firewalld; UFW ) // 3 implemented; iptables/pf deleted
func New(b Backend, namespace string, opts ...Option) (Manager, error)
func Detect(ctx context.Context) []Backend

type Manager interface {
    ApplyRule(ctx context.Context, r Rule) error
    RemoveRule(ctx context.Context, id string) error
    List(ctx context.Context) ([]Rule, error)
    Namespace() string
}
type Protocol string ; const ( ProtocolTCP Protocol = "tcp"; ProtocolUDP = "udp"; ProtocolAny = "" )
type Rule struct { ID string; Allow bool; Protocol Protocol; Port int; Source, Dest string }
var ErrInvalidRule, ErrInvalidNamespace error
```

- Already a `Manager`; just folds `Backend` into `New` (drops the global
  `SetBackend`) — **one of the two packages that keeps a real `Backend` arg.**
- **Preserved:** namespace isolation, `validateRule` (ID/port/protocol/addr) +
  per-backend scope (firewalld v1 allow-only), idempotent apply / no-op remove.
- Note the firewalld v1 scope is narrower (no source/dest) — surfaced via
  `ErrInvalidRule` when a caller exceeds it. Documented, not silently dropped.

---

## 7. `fs`

**F1 — consolidate the write surface — RATIFIED.** The four atomic-ish write
paths (`WriteFile` priv-tee, `WriteFileAtomic` priv string-mode, `AtomicWriteFile`
non-priv `os.FileMode`, `SafeReplaceFile` symlink-safe) collapse into **one
`WriteFile` that is always atomic + symlink-safe**, `os.FileMode` everywhere
(drop string `"0644"`), options struct.

```go
// Implemented as New(runner exec.Runner) (Manager, error): no fs option exists,
// so the speculative variadic was dropped (YAGNI / clean-break). Add it back the
// day a real Option lands.
func New(runner exec.Runner) (Manager, error) // single-impl-by-nature; runner required

type Manager interface {
    ReadFile(ctx context.Context, path string) ([]byte, error)
    WriteFile(ctx context.Context, path string, data []byte, opts WriteOptions) error
    Exists(ctx context.Context, path string) (bool, error)
    Mkdir(ctx context.Context, path string, opts MkdirOptions) error
    Remove(ctx context.Context, path string) error    // was RemoveStrict; error-swallowing Remove dropped
    RemoveDir(ctx context.Context, path string) error  // deny-by-default + symlink-safe
    Copy(ctx context.Context, src, dst string, opts WriteOptions) error
    SetMode(ctx context.Context, path string, mode os.FileMode) error
    SetOwnership(ctx context.Context, path, owner, group string) error
    SetOwnershipRecursive(ctx context.Context, path, owner, group string) error // no longer leaks Result
    IsReadOnly(ctx context.Context, path string) (bool, error)
    RemountRW(ctx context.Context, path string) error
}
type WriteOptions struct {
    Mode         os.FileMode // 0 = 0644
    Owner, Group string
    Backup       string // "" = none; else copy-then-replace (was SafeBackupAndReplace)
}
type MkdirOptions struct { Mode os.FileMode; Owner, Group string; Recursive bool }

// fd-anchored primitives + path predicates stay exported (the agent uses them directly):
func OpenRealDir(path string) (*os.File, error)
func FchownNoFollow(path string, uid, gid int) error
func SetDirPermissionsNoFollow(path string, mode os.FileMode, uid, gid int) error
func ResolveOwnership(owner, group string) (uid, gid int, err error)
func IsProtectedPath(path string) bool ; func IsUnderProtectedPrefix(path string) bool
func ValidatePath(path string) error ; func ResolveAndValidatePath(path string) (string, error)
var ErrInvalidPath error
```

- **`WriteFile` picks fd-safe (`O_NOFOLLOW`+`renameat2`) when `Runner.Backend()
  == Direct` (root), else the sudo tee/mv path** — exactly today's privilege-keyed
  behaviour, now driven by the injected Runner instead of a global. This is why
  `Runner` exposes `Backend()`.
- **Preserved:** every symlink/TOCTOU defense (fd-anchored ops, `RENAME_NOREPLACE`,
  deny-by-default `IsUnderProtectedPrefix` subtree refusal), atomic-write
  ordering (mode-before-rename, fsync), `ValidatePath` (NUL / leading-`-`).
- `Ownership`/`GetOwnership`/`AssertRealDir` retained as helpers; the three
  separate atomic constructors are gone in favor of `WriteFile`+`WriteOptions`.

---

## 8. `reboot`

```go
func New(opts ...Option) (Manager, error)
type Manager interface {
    IsRequired(ctx context.Context) (bool, error) // was IsRequired() bool — now ctx + honest error
    Schedule(ctx context.Context, opts ScheduleOptions) error
    Cancel(ctx context.Context) error
}
type ScheduleOptions struct { Delay string; Message string } // Delay "" = "+1"
```

- `IsRequired` gains `ctx` and **returns the error** instead of swallowing it
  (caller decides if a probe failure means "assume no"). Multi-distro detection
  (Debian `/var/run/reboot-required` → Fedora `needs-restarting -r`) stays internal.

---

## 9. `notify`

```go
func New(opts ...Option) (Manager, error)
type Manager interface {
    NotifyAll(ctx context.Context, n Notification) error            // was (…) with NO return
    NotifyUsers(ctx context.Context, users []string, n Notification) error
}
type Notification struct {
    Title, Body string
    Urgency     Urgency // was hardcoded "critical"
    AppName     string  // was hardcoded "Power Manage"
    Icon        string  // was hardcoded "dialog-warning"
}
type Urgency int ; const ( UrgencyLow Urgency = iota; UrgencyNormal; UrgencyCritical )
```

- **Both methods now return `error`** (today they return nothing and swallow
  everything — the design's "never silently ignore errors" rule). Best-effort
  per-recipient failures aggregate into the returned error; the caller chooses to
  ignore. The hardcoded `notify-send` flags become `Notification` fields.
- **Preserved:** wall + desktop fan-out, graphical-session filtering
  (`Remote=no`, `Type ∈ {x11,wayland,mir}`), `runuser`+`DBUS_SESSION_BUS_ADDRESS`.

---

## 10. `inventory`

```go
func New(opts ...Option) (Collector, error)
type Collector interface {
    SystemInfo(ctx context.Context) (SystemInfo, error)
    OSInfo(ctx context.Context) (OSInfo, error)                 // gains ctx for uniformity
    Disks(ctx context.Context) ([]DiskInfo, error)
    NetworkInterfaces(ctx context.Context) ([]NetworkInterface, error)
}
type SystemInfo struct { Hostname, CPUModel string; CPUCores int; MemoryTotalMB int64; Arch, KernelVersion string }
type OSInfo    struct { Name, Version, ID, PrettyName, VersionID, Arch string }
type DiskInfo  struct { Device, Size, Type, Mount string }
type NetworkInterface struct { Name, MAC string; Addresses []string; State string }
```

- Drop the `Get` prefix (`GetSystemInfo`→`SystemInfo`). `OSInfo` gains `ctx` for
  shape-uniformity even though it's file-only. Structs unchanged (good as-is).

---

## 11. `desktop`

```go
func New(runner exec.Runner, opts ...Option) (Manager, error) // WithHomeRoot(dir) for tests
type Manager interface {
    ActiveSessions(ctx context.Context) ([]Session, error)
    HomeUsers(ctx context.Context) ([]Session, error)
    UsersWithFlatpakInstall(ctx context.Context, appID string) ([]Session, error)
    RunAsCommand(ctx context.Context, s Session, opts RunAsOptions, name string, args ...string) (*exec.Cmd, error)
}
type Session struct { ID, Username string; UID, GID int; Home, RuntimeDir, Type string }
type RunAsOptions struct { ExtraEnv []string }
func EnvFor(s Session) []string ; func UserPath(s Session) string // pure helpers stay
```

- `HomeUsers`/`UsersWithFlatpakInstall` gain `ctx`. `RunAsCommand`'s positional
  `extraEnv` becomes `RunAsOptions`.
- **Runner-driven probes:** the `loginctl` PROBES (`ActiveSessions` and helpers)
  run through the injected Runner, so they inherit the forced **C locale** — the
  no-logind / no-session stderr fingerprints are matched against stable English
  regardless of host locale. **`RunAsCommand` is the deliberate exception:** it
  builds a command run ON BEHALF OF a signed-in user (Flatpak install, user
  script) whose output the SDK does NOT parse, so it does NOT go through the
  Runner and keeps the **user's own locale** — forcing C there would be wrong.
- **Preserved:** absolute `loginctl`/`runuser` paths, env-wholesaling (agent env
  NOT inherited; curated `UserPath` applied last), forced `Home` workdir.

---

## 12. `osquery`

```go
func New(runner exec.Runner) (Querier, error) // was NewClient; eager ErrNotInstalled probe preserved
type Querier interface {
    IsInstalled(ctx context.Context) bool // LIVE re-probe (detects removal at runtime)
    ListTables(ctx context.Context) ([]string, error)
    Query(ctx context.Context, q *pb.OSQuery) (*pb.OSQueryResult, error)
    QueryTable(ctx context.Context, table string) ([]*pb.OSQueryRow, error)
    QuerySQL(ctx context.Context, sql string) ([]*pb.OSQueryRow, error)
}
var ErrNotInstalled, ErrQueryFailed error
```

- `New` keeps the current **eager** behaviour: it probes for the osqueryi binary
  and returns `ErrNotInstalled` when absent (a caller learns at construction).
  The free `IsInstalled()` function is removed — `IsInstalled(ctx)` is a Querier
  method that re-probes live so a binary removed during the agent's lifetime is
  reported as gone. No `opts ...Option` — there is no real option to configure.

- **Preserved verbatim — the security core:** the credential-table **deny-list**
  (`shadow`, `process_envs`, `crontab`, `shell_history`, `sudoers`),
  case/whitespace-insensitive, short-circuit before exec; the table-name regex;
  the `RawSql` escape hatch gated only on `Query` (the CA-signed path), never on
  `QueryTable`. The deprecated `Registry` (implicit `context.Background()`)
  **deleted**.
- **O1 — proto coupling — RATIFIED (keep `pb.*`).** The interface keeps the
  generated `*pb.OSQuery`/`*pb.OSQueryResult` types (agent-aligned, zero mapping).
  osquery is an internal agent capability; decoupling buys little for real cost.

---

## 13. `terminal`

```go
func New() (Manager, error) // NO Runner — a PTY is a long-lived stream the captured-output Runner can't model
type Manager interface {
    Open(ctx context.Context, cfg SessionConfig) (*Session, error) // was Start(cfg) — ctx gates ALLOCATION only
}
type SessionConfig struct {
    User, Shell string
    Cols, Rows  uint16
    Env         []string
    WorkDir     string
}
// *Session methods unchanged in spirit, with one fix:
func (s *Session) Read(p []byte) (int, error)
func (s *Session) Write(p []byte) (int, error)
func (s *Session) Resize(cols, rows uint16) error // NOW validates dims (WS15) before Setsize
func (s *Session) Close() error
func (s *Session) Wait() (int, error)
func (s *Session) Done() <-chan struct{}
const ( DefaultShell = "/bin/bash"; DefaultCols = 80; DefaultRows = 24 )
func TTYUsername(name string) string ; func TTYUID(uid, offset int) int ; func OriginalUID(ttyUID, offset int) int
```

- `Open` gains `ctx` (cancellable PTY allocation). **`Resize` validates dims**
  (`validateDims`, the WS15 fix) before `Setsize` — today it accepts any uint16.
- **Preserved:** absolute-shell + exists + executable + not-dir checks, the
  conditional UID/GID switch (seccomp/no_new_privs parity), curated PATH +
  env-wholesaling, process-group SIGTERM on `Close`, the reaper goroutine.

---

## 14. Cross-cutting decisions

- **U1 — `Secret` type — RATIFIED (yes).** `type Secret` lives in `exec`,
  constructed via `exec.NewSecret(string)` (newline/CR-rejecting),
  `String()`→`"[REDACTED]"`, `Reveal()` for the single sink that needs the
  bytes. Used for passwords / LUKS keys / wifi PSK + client key — see the
  `Secret` params in §2, §4, §5. A credential can no longer reach a log by
  accident, and sensitive params are visually distinct.
  - **Enforced by a fitness function, not just convention.** A `Reveal()`-only-
    from-known-sinks archtest (design §6) discovers every `.Reveal()` call site
    across `sys/*` + `pkg` and fails on any outside the allowlisted credential
    sinks (chpasswd/cryptsetup stdin, PSK keyfile writer), with no-stale +
    matches-zero guards. Without it, `Reveal()` is one careless `slog`/`Sprintf`
    away from defeating the redaction; the unit tier only pins that a `Secret`
    never lands in a recorded `Command.Args`, which wouldn't catch a direct log.
- **O1 — proto coupling — RATIFIED (keep `pb.*`).** `osquery` keeps the
  generated `*pb.OSQuery`/`*pb.OSQueryResult` types (§12). osquery is an internal
  agent capability; decoupling buys little for real cost.
- **F1 — fs write consolidation — RATIFIED (consolidate).** One
  `WriteFile`+`WriteOptions`, always atomic + symlink-safe, `os.FileMode`
  throughout (§7). Replaces the four write variants.
- **P1 — apt extras — RATIFIED (generalize or fold).** `Autoremove(ctx)` is a
  first-class no-op-where-absent interface method; `DistUpgrade`→`Upgrade(nil)`;
  `FixBroken`→`Repair`. No typed-assertion side-interface (§1).
- **Boolean→enum sweep:** `GeneratePassword(complex bool)`→`Complexity`,
  `notify` urgency, `pkg`'s `useSudo`→Runner. Done above.
- **Deleted everywhere:** every `Set*Backend`/`Current*Backend` global + their
  deprecated aliases; `Query`/`Check` ctx-less exec helpers; `ChownRecursive`
  alias; the `osquery.Registry` shim; the three separate `fs` atomic constructors.
