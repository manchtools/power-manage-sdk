# Power Manage SDK

Shared protocol definitions, generated code, and client libraries for Power Manage. Used by the [Control Server](../server/cmd/control/), [Gateway](../server/cmd/gateway/), [Agent](../agent/), and [Web UI](../web/).

## Contents

```
sdk/
├── proto/pm/v1/           Protocol Buffer source definitions
│   ├── common.proto         Base types, enums, error codes
│   ├── actions.proto        Action types, parameters, scheduling
│   ├── agent.proto          Bidirectional streaming (Agent ↔ Gateway)
│   ├── control.proto        Control API (164 RPCs)
│   ├── device_auth.proto    Agent enrollment via local unix socket
│   └── internal.proto       Gateway-to-control proxy for credential operations
│
├── gen/go/pm/v1/           Generated Go code (protobuf + Connect RPC)
│   ├── *.pb.go               Message types with injected validation tags
│   └── pmv1connect/          Connect RPC client and server interfaces
│
├── go/
│   ├── client.go            Agent streaming client (mTLS, heartbeat, action dispatch)
│   ├── crypto/              CSR generation and certificate utilities
│   ├── logging/             Structured logging setup (slog)
│   ├── pkg/                 Package manager abstraction library
│   │   ├── apt.go             APT (Debian/Ubuntu)
│   │   ├── dnf.go             DNF (Fedora/RHEL)
│   │   ├── pacman.go          Pacman (Arch Linux)
│   │   ├── zypper.go          Zypper (openSUSE)
│   │   └── flatpak.go         Flatpak (cross-distro)
│   ├── sys/                 Linux system management libraries
│   │   ├── exec/              Command execution with pluggable PrivilegeBackend (sudo/doas)
│   │   ├── fs/                Filesystem operations (read, write, atomic, permissions)
│   │   ├── service/           Service manager — pluggable ServiceBackend (systemd/openrc/runit/s6)
│   │   ├── encryption/        Disk encryption — pluggable Backend (luks/geli/cgd)
│   │   ├── network/           WiFi connection profiles — pluggable WifiBackend (nm/connman/wpa/iwd)
│   │   ├── firewall/          Packet filter — pluggable Backend (nftables/iptables/firewalld/ufw/pf)
│   │   ├── dns/               Resolver config — pluggable Backend (resolved/resolvconf/dnsmasq/nm)
│   │   ├── netconfig/         IP / routing / DHCP — pluggable Backend (nm/networkd/netplan/dhcpcd/ifupdown)
│   │   ├── notify/            Desktop notification utilities
│   │   ├── osquery/           osquery integration (lazy-init, system queries)
│   │   ├── reboot/            Reboot scheduling
│   │   ├── terminal/          PTY session management
│   │   └── user/              User & group management, password generation
│   ├── validate/            Input validation (struct tag validator + ULID rule)
│   └── verify/              Action payload signature verification
│
├── ts/                      TypeScript SDK (framework-agnostic browser utilities)
│   ├── client.ts              Connect-RPC client with all API methods
│   ├── auth.ts                JWT token management, persistent auth storage
│   ├── errors.ts              Error code extraction from Connect-RPC errors
│   ├── action-types.ts        Action type constants and display helpers
│   ├── config.ts              Configuration utilities
│   ├── offline.ts             Offline support utilities
│   └── index.ts               Package exports
│
├── test/                    Integration test infrastructure
│   ├── Dockerfile.integration  Test container (systemd + sudo)
│   └── run-tests.sh           Test runner script
│
└── Makefile                Proto generation commands
```

## Proto Definitions

Six proto files define the entire API surface:

| File | Purpose |
|------|---------|
| `common.proto` | ULID identifiers, execution status, assignment modes, error detail codes |
| `actions.proto` | Action types (package, update, repository, app_image, deb, rpm, flatpak, shell, service, file, directory, user, group, ssh, sshd, admin_policy, lps, encryption, wifi, agent_update), parameters, scheduling. Several capability areas are modelled with a backend enum so the same action type can target multiple implementations (e.g. `AdminPolicyParams.backend = sudo|doas`, `ServiceParams.backend = systemd|openrc|…`). See [docs/backend-pattern.md](docs/backend-pattern.md). |
| `agent.proto` | `AgentService` — bidirectional streaming RPC + action sync, heartbeat, output streaming, OS queries, log queries. Hello includes `arch` for platform detection. |
| `control.proto` | `ControlService` — full RPC surface (~164 methods) covering users, devices, groups, actions, sets, definitions, assignments, tokens, executions, roles, user groups, identity providers, SCIM, TOTP, audit, compliance policies, certificate renewal, search, server settings, and more |
| `device_auth.proto` | `DeviceAuthService` — agent enrollment via local unix socket |
| `internal.proto` | `InternalService` — gateway-to-control proxy for credential-bearing operations (LUKS keys, LPS passwords) and agent auto-update info |

## Go SDK

### Streaming Client

`go/client.go` provides the agent-side streaming client:

```go
import sdk "github.com/manchtools/power-manage/sdk/go"

client, _ := sdk.NewClient(gatewayURL,
    sdk.WithMTLS(certFile, keyFile, caFile),
)
client.Run(ctx, handler)
```

Features: mTLS authentication, automatic heartbeat, action result reporting, live output streaming, security alerts.

#### Stream-loop robustness

The receive loop is hardened against a compromised or buggy gateway:

- **Inbound size bound.** `NewClient` wires `connect.WithReadMaxBytes(maxInboundMessageBytes)` (16 MiB). An over-large `ServerMessage` is refused with a resource-exhausted error and the connection is torn down cleanly (the loop reconnects) instead of allocating the frame — closing an OOM/DoS vector.
- **Per-message panic isolation.** `dispatchServerMessage` runs each message under a scoped `recover()`: a panic inside any handler method is caught, logged, and turned into a non-fatal dropped frame so one bad handler invocation cannot crash-loop the whole agent (fleet DoS). Genuine fatal stream send/receive errors still propagate.
- **Bounded, panic-safe goroutine fan-out.** The server-originated `RequestInventory` and `RevokeLuksDeviceKey` legs (and the inventory ticker) run through `safeGo` — a spawned goroutine with its own deferred `recover()` — and are gated behind bounded semaphores so a flood of frames cannot spawn unbounded goroutines or crash the process from a goroutine panic.
- **Malformed-oneof nil-guards.** A `ServerMessage` whose inner oneof payload is nil (e.g. a `ServerMessage_Action` with a nil `ActionDispatch`) is logged and dropped, never dereferenced.

### Certificate Renewal

`go/client.go` also provides a standalone `RenewCertificate` function for certificate rotation:

```go
result, _ := sdk.RenewCertificate(ctx, controlURL, csrPEM, currentCertPEM)
// result.Certificate — new signed certificate (PEM)
// result.NotAfter    — certificate expiry time
// result.CACert      — active CA certificate (PEM), for CA rotation
```

The agent presents its current (still valid) certificate and a new CSR. The Control Server verifies the certificate, checks the fingerprint against the database, signs the new CSR, and returns the active CA certificate. If the CA has been rotated, the agent should update its stored CA certificate.

**Bootstrap transport hardening.** `RegisterAgent` and `RenewCertificate` are the unauthenticated bootstrap calls; their default HTTP client is bounded (request timeout + TLS 1.3 floor) so a hung or malicious control endpoint cannot wedge enrollment/renewal. Proxy support is retained for enterprise deployments (the channel is TLS-authenticated and the optional enrollment CA-pin catches a wrong-CA outcome). A `ClientOption` (the mTLS variants) overrides the client entirely.

**Enrollment trust helpers** (`go/crypto`):

```go
fp, _ := crypto.CAFingerprintFromPEM(caPEM)        // lowercase-hex SHA-256 of the CA DER
err := crypto.VerifyCAContinuity(oldCAPEM, newCAPEM) // accept only an identical or cross-signed CA
```

`CAFingerprintFromPEM` is byte-identical to the control server's `ca.FingerprintFromPEM`, so an operator-supplied out-of-band pin (e.g. `openssl x509 -in ca.crt -outform DER | sha256sum`) matches what the agent derives from the registration-returned CA. `VerifyCAContinuity` guards certificate rotation: a returned CA is adopted only when it is byte-identical to, or cross-signed by, the enrolled CA — refusing an unrelated trust-anchor swap.

### Package Manager Library

`go/pkg/` abstracts five Linux package managers behind a unified interface with a builder API:

```go
import "github.com/manchtools/power-manage/sdk/go/pkg"

pm, _ := pkg.New()                          // auto-detect
pm.Install("nginx").Version("1.24.0").Run() // fluent builder
updates, _ := pm.ListUpgradable()           // query methods
```

See the [package manager README](go/pkg/README.md) for the full API.

### System Management Libraries

`go/sys/` provides opinionated Linux system management utilities. All privileged operations run through the configured privilege backend (sudo or doas, see `exec.SetPrivilegeBackend`), so the calling process does not need to be root.

#### `sys/exec` — Command Execution

```go
import "github.com/manchtools/power-manage/sdk/go/sys/exec"

result, err := exec.Run(ctx, "ls", "-la")                               // basic command
result, err := exec.Privileged(ctx, "systemctl", "restart", "nginx")     // through sudo/doas
stdout, err := exec.Query("hostname")                                    // quick query
ok := exec.Check("which", "nginx")                                       // boolean check
```

Key features:
- Streaming output via `RunStreaming` with per-line callbacks
- Automatic path resolution for the privileged commands
- Output truncation at 1 MiB to prevent memory issues

#### `sys/fs` — Filesystem Operations

```go
import "github.com/manchtools/power-manage/sdk/go/sys/fs"

content, err := fs.ReadFile(ctx, "/etc/hostname")
err := fs.WriteFileAtomic(ctx, "/etc/nginx/nginx.conf", content, "0644", "root", "root")
exists := fs.FileExists(ctx, "/etc/motd")
err := fs.MkdirWithPermissions(ctx, "/opt/app", "0755", "app", "app", true)
```

All operations escalate via the configured privilege backend (sudo or doas). `WriteFileAtomic` uses a write-then-rename sequence so concurrent readers see either the old or new file, never a half-written one. For fsync-level durability + an unguessable temp suffix, use `AtomicWriteFile` in `atomic_write.go`.

#### `sys/user` — User & Group Management

```go
import "github.com/manchtools/power-manage/sdk/go/sys/user"

info, err := user.Get("deploy")              // get user info (UID, GID, shell, groups, locked)
err := user.Create(ctx, "deploy", "-m", "-s", "/bin/bash")
err := user.GroupCreate(ctx, "developers")
err := user.GroupAddUser(ctx, "deploy", "developers")
password, err := user.GeneratePassword(24, true)  // 24 chars, complex
err := user.SetPassword(ctx, "deploy", password)
```

#### `sys/osquery` — OS Query Integration

```go
import "github.com/manchtools/power-manage/sdk/go/sys/osquery"

oq := osquery.New()                                // lazy-init, detects installs without restart
rows, err := oq.Query(ctx, "os_version", nil, 0)   // query a table
```

#### `sys/encryption` — Disk Encryption

```go
import "github.com/manchtools/power-manage/sdk/go/sys/encryption"

err := encryption.AddKey(ctx, devicePath, existingKey, newKey)
err := encryption.AddKeyToSlot(ctx, devicePath, slot, existingKey, newKey)
```

`encryption` exposes a pluggable Backend (LUKS today; geli/cgd planned). Call `encryption.SetBackend(encryption.BackendLUKS)` once at startup.

#### `sys/service` — Service Manager

```go
import "github.com/manchtools/power-manage/sdk/go/sys/service"

status, err := service.Status("nginx.service")  // {Enabled, Active, Masked, Static}
err := service.EnableNow(ctx, "nginx.service")
err := service.WriteUnit(ctx, "myapp.service", unitContent)
err := service.DaemonReload(ctx)
```

`service` selects between systemd / openrc / runit / s6 via `service.SetServiceBackend(...)`.

### Action Signature Verification

`go/verify/` provides action payload signature verification for agents:

```go
import "github.com/manchtools/power-manage/sdk/go/verify"

signer := verify.NewActionSigner(caKey)        // server-side signing
verifier := verify.NewActionVerifier(caCert)   // agent-side verification
err := verifier.Verify(action)                 // verify action signature
```

Beyond actions, the same CA key signs the four root **stream-RPCs** (osquery,
log query, LUKS revoke, inventory) under per-surface **disjoint domains** so a
signature for one surface can never be replayed against another:

```go
// Control server signs the canonical bytes of each message (signature field
// cleared) under that surface's domain; the agent verifies before any root work.
canonical, _ := verify.OSQueryCanonical(q)                       // also LogQueryCanonical / RevokeLuksDeviceKeyCanonical / RequestInventoryCanonical
sig, _  := signer.SignDomain(verify.OSQuerySignatureDomain, canonical)
err     := verifier.VerifyDomain(verify.OSQuerySignatureDomain, canonical, sig)
```

### Input Validation

`go/validate/` wraps the [go-playground/validator](https://github.com/go-playground/validator) library with the project's custom rules (today: a `ulid` tag for ULID identifiers). RPC handlers and other server code use it via:

```go
import "github.com/manchtools/power-manage/sdk/go/validate"

v := validate.NewValidator()                       // returns a *validator.Validate with rules registered
msg, ok := validate.Struct(v, request)             // returns a formatted error message
text := validate.FormatFieldError(fieldErr)        // single-field formatter
```

Field rules are declared via `validate:"..."` struct tags injected into the generated proto types (`@gotags: validate:"required,ulid"` etc.).

### Running SDK Tests

The `sys/` packages include integration tests that run inside a systemd-enabled container:

```bash
./sdk/test/run-tests.sh
```

This builds a test image, boots systemd, and runs all tests as a non-root user with sudo access.

## TypeScript SDK

The `ts/` directory contains framework-agnostic browser utilities used by the web frontend:

| File | Purpose |
|------|---------|
| `client.ts` | Connect-RPC client wrapping the full ControlService surface (~164 RPCs) |
| `auth.ts` | JWT token management with persistent auth storage ("keep me signed in") |
| `errors.ts` | Error code extraction from `ConnectError` details (`getErrorCode()`) |
| `action-types.ts` | Action type constants, display names, and icon mappings |
| `config.ts` | Configuration utilities |
| `offline.ts` | Offline support utilities |

Generated TypeScript types (protobuf messages) are produced separately via Buf:

```bash
cd ../web && npx buf generate   # outputs to web/src/lib/gen/pm/v1/
```

Or download the `ts-sdk.tar.gz` from the [latest release](https://github.com/MANCHTOOLS/power-manage-sdk/releases/latest) and extract into your project.

## Regenerating Code

```bash
# Go (protobuf + Connect RPC + validation tags)
make generate

# TypeScript (from the web directory)
cd ../web && npx buf generate

# Install Go proto tools
make install-tools
```

## Release coordination

Downstream repos (agent, server) pin the SDK to a specific commit via a Go pseudo-version. SDK `main` can change without breaking downstream builds; bumps are explicit PRs. For the full release flow — pinning, cross-cutting development with `go.work`, tagging conventions, and the separation between human-readable GitHub Release tags and Go module pins — see [docs/release-coordination.md](docs/release-coordination.md).

## License

MIT — see [LICENSE](LICENSE).
