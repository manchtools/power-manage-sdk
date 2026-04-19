# Backend pattern for multi-implementation packages

Several SDK packages abstract over multiple real-world implementations of
the same capability — there's more than one way to manage privilege
escalation (sudo, doas), service units (systemd, OpenRC, runit, s6),
disk encryption (LUKS, GELI, CGD), WiFi (NetworkManager, connman,
wpa_supplicant, iwd), and so on. This document describes the single
shape every one of those packages uses, so the next contributor adding
a `sys/<new>` extension point does not have to reverse-engineer the
existing packages.

## Why this pattern exists

An earlier version of the SDK hard-coded `sudo` in every call site.
Adding doas support would have been a 71-file rename that broke every
downstream consumer. The pattern below turns that kind of rename into
a copy-paste of a ~60-line file plus one proto enum addition.

The goals:

1. **Agents choose their backend explicitly** — no runtime detection
   that can silently pick the wrong tool.
2. **Default works out of the box** — agents that don't opt in get the
   dominant implementation for their platform.
3. **Unknown values don't regress a configured agent** — a zero-valued
   proto enum from a downstream caller can't overwrite a backend the
   agent explicitly selected at startup.
4. **Unimplemented backends fail loudly, not silently** — callers get
   a wrapped sentinel error they can `errors.Is` against.
5. **The shape is identical everywhere** — so a reader who understands
   one `sys/*` backend package understands all of them.

## The Go shape

Every pluggable `sys/<capability>` package provides exactly this set of
symbols. The atomic dispatch is lock-free on the read path, so there's
no per-call cost on top of the actual work.

```go
package foo

import (
    "context"
    "errors"
    "fmt"
    "sync/atomic"
)

// Backend identifies which implementation the SDK targets.
type Backend int

const (
    BackendDefault Backend = 0  // the canonical implementation
    BackendOther   Backend = 1
    // ...
)

// ErrBackendNotSupported is the sentinel returned for unimplemented
// backends. Callers errors.Is against it to distinguish capability
// gaps from transient failures.
var ErrBackendNotSupported = errors.New("foo backend not supported")

var backend atomic.Int32

// SetBackend selects the active backend. Call once at startup. Unknown
// values are ignored so a zero-valued proto enum cannot regress an
// explicitly-set backend.
func SetBackend(b Backend) {
    switch b {
    case BackendDefault, BackendOther:
        backend.Store(int32(b))
    }
}

// CurrentBackend returns the active backend.
func CurrentBackend() Backend {
    return Backend(backend.Load())
}

// Stringer gives log output a clear backend name.
func (b Backend) String() string {
    switch b {
    case BackendDefault:
        return "default"
    case BackendOther:
        return "other"
    default:
        return fmt.Sprintf("unknown(%d)", int(b))
    }
}

func unsupported(op string) error {
    return fmt.Errorf("%w: %s on backend %s", ErrBackendNotSupported, op, CurrentBackend())
}

// Capability function — public API dispatches to the active backend.
func DoThing(ctx context.Context, arg string) error {
    switch CurrentBackend() {
    case BackendDefault:
        return doThingDefault(ctx, arg)
    default:
        return unsupported("DoThing")
    }
}
```

Backend-specific implementations live in sibling files with the backend
name appended (`doThingDefault`, `doThingOther`) and are unexported.
Callers only ever see the public dispatch function.

## The proto shape

Each pluggable area gets a matching enum in `proto/pm/v1/actions.proto`
(or the closest proto file for the feature). The default value is always
`<AREA>_BACKEND_<CANONICAL> = 0` so an uninitialised field degrades
sensibly.

```proto
enum FooBackend {
  FOO_BACKEND_DEFAULT = 0;   // canonical implementation
  FOO_BACKEND_OTHER = 1;
}

message FooParams {
  // ... existing fields ...

  // Backend. Defaults to FOO_BACKEND_DEFAULT.
  // @gotags: validate:"omitempty"
  FooBackend backend = N;
}
```

When a backend enum is needed without a matching action type yet (e.g.,
`FirewallBackend` — the feature is on the roadmap but not shipping this
release), the enum still lives in `actions.proto` so the wire format is
committed up front.

## Where the backend is set

The agent is the canonical caller. It reads its configured backend(s)
once at startup and passes them to each package:

```go
// cmd/power-manage-agent/main.go (illustration)
sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackend(cfg.PrivilegeBackend))
service.SetServiceBackend(service.ServiceBackend(cfg.ServiceBackend))
encryption.SetBackend(encryption.Backend(cfg.EncryptionBackend))
// ...
```

The server does not call these setters — the server's job is to produce
`Params` messages with the right `backend` field; the agent translates
that into the SDK-level backend selection as part of dispatching the
action.

## Adding a new backend

Two cases: adding an implementation to an existing backend package, or
creating a whole new pluggable capability area.

### Case A: new implementation for an existing package

1. Add the new value to the proto enum (e.g., `SERVICE_BACKEND_OPENRC`)
   and to the Go `Backend` type in the matching package.
2. Implement the unexported helpers in a new file (e.g.,
   `sys/service/openrc.go`) — do not add a new `package` declaration,
   these live in the same package as the public API.
3. Add the case to every public function's dispatch switch.
4. Update the package's `String()` method.
5. Add a test case to the package's `*_test.go` covering the
   Stringer output and at least one `ErrBackendNotSupported` assertion.

### Case B: new pluggable capability area

1. Add the proto enum in `actions.proto` (even without a matching action
   type yet — forward-compat).
2. Create `go/sys/<area>/<area>.go` using the template above.
3. Create `go/sys/<area>/<area>_test.go` covering:
   - default value
   - unknown-value-ignored guard
   - sentinel error from unimplemented backends
   - Stringer
4. Add the package to the tree listing in `README.md`.
5. Regenerate proto (`make generate`).
6. Update this doc's reference list.

## Packages using this pattern today

| Package | Setter | Default | Other backends |
|---|---|---|---|
| [`go/sys/exec`](../go/sys/exec/) | `SetPrivilegeBackend` | `PrivilegeBackendSudo` | `PrivilegeBackendDoas` |
| [`go/sys/service`](../go/sys/service/) | `SetServiceBackend` | `ServiceBackendSystemd` | OpenRC, runit, s6 (not yet implemented) |
| [`go/sys/encryption`](../go/sys/encryption/) | `SetBackend` | `BackendLUKS` | GELI, CGD (not yet implemented) |
| [`go/sys/network`](../go/sys/network/) | `SetWifiBackend` | `WifiBackendNetworkManager` | connman, wpa_supplicant, iwd (not yet implemented) |
| [`go/sys/firewall`](../go/sys/firewall/) | `SetBackend` | `BackendNftables` | iptables, firewalld, ufw, pf (not yet implemented) |
| [`go/sys/dns`](../go/sys/dns/) | `SetBackend` | `BackendResolved` | resolvconf, dnsmasq, NetworkManager (not yet implemented) |
| [`go/sys/netconfig`](../go/sys/netconfig/) | `SetBackend` | `BackendNetworkManager` | systemd-networkd, netplan, dhcpcd, ifupdown (not yet implemented) |

## Anti-patterns — things not to do

- **Don't runtime-detect which tool is installed and pick automatically.**
  That's what the pre-refactor `sys/exec` did — it resolved `sudo` via
  `LookPath` at every call site. Silent auto-detection couples the agent's
  behaviour to whatever happened to be installed on the disk, which makes
  debugging misconfigured devices painful. Explicit beats clever here.
- **Don't build a generic `BackendRegistry[T]`.** Seven instances of a
  60-line file is cheaper to read and change than one generic framework.
  If a future backend has materially different needs, diverge; don't
  bend the shared shape.
- **Don't use a boolean flag for two-implementation areas.** Even when
  there's only one alternative (sudo vs doas), use an enum so adding a
  third implementation later doesn't require renaming the field.
- **Don't panic or os.Exit from these packages.** Return
  `ErrBackendNotSupported` or a wrapping error. Agents decide how to
  surface capability gaps to operators.
- **Don't rename existing enum values after launch.** The enum numbers
  are wire-format; their names are API. Add a new value, deprecate the
  old one in comments, but don't rename.
