# Power Manage SDK

Shared protocol definitions, generated code, and client libraries for Power Manage. Used by the [Control Server](../server/cmd/control/), [Gateway](../server/cmd/gateway/), [Agent](../agent/), and [Web UI](../web/).

## Contents

```
sdk/
├── proto/pm/v1/           Protocol Buffer source definitions
│   ├── common.proto         Base types, enums, identifiers
│   ├── actions.proto        Action types, parameters, scheduling
│   ├── agent.proto          Bidirectional streaming (Agent ↔ Gateway)
│   └── control.proto        Control API (136 RPCs)
│
├── gen/go/pm/v1/           Generated Go code (protobuf + Connect RPC)
│   ├── *.pb.go               Message types with injected validation tags
│   └── pmv1connect/          Connect RPC client and server interfaces
│
├── go/
│   ├── client.go            Agent streaming client (mTLS, heartbeat, action dispatch)
│   ├── pkg/                 Package manager abstraction library
│   │   ├── apt.go             APT (Debian/Ubuntu)
│   │   ├── dnf.go             DNF (Fedora/RHEL)
│   │   ├── pacman.go          Pacman (Arch Linux)
│   │   ├── zypper.go          Zypper (openSUSE)
│   │   └── flatpak.go         Flatpak (cross-distro)
│   └── sys/                 Linux system management libraries
│       ├── exec/              Command execution (sudo, streaming, queries)
│       ├── fs/                Filesystem operations (read, write, atomic, permissions)
│       ├── user/              User & group management, password generation
│       └── systemd/           Systemd unit management
│
├── test/                    Integration test infrastructure
│   ├── Dockerfile.integration  Test container (systemd + sudo)
│   └── run-tests.sh           Test runner script
│
└── Makefile                Proto generation commands
```

## Proto Definitions

Four proto files define the entire API surface:

| File | Purpose |
|------|---------|
| `common.proto` | ULID identifiers, execution status, assignment modes |
| `actions.proto` | 16 action types (package, update, repository, app_image, deb, rpm, flatpak, shell, systemd, file, directory, reboot, sync, user, group, luks), parameters, scheduling |
| `agent.proto` | `AgentService` — bidirectional streaming RPC + action sync, heartbeat, output streaming, OS queries |
| `control.proto` | `ControlService` — 136 RPCs for users, devices, groups, actions, sets, definitions, assignments, tokens, executions, roles, user groups, identity providers, SCIM, TOTP, audit, compliance policies, certificate renewal, and more |

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

### Certificate Renewal

`go/client.go` also provides a standalone `RenewCertificate` function for certificate rotation:

```go
result, _ := sdk.RenewCertificate(ctx, controlURL, csrPEM, currentCertPEM)
// result.Certificate — new signed certificate (PEM)
// result.NotAfter    — certificate expiry time
// result.CACert      — active CA certificate (PEM), for CA rotation
```

The agent presents its current (still valid) certificate and a new CSR. The Control Server verifies the certificate, checks the fingerprint against the database, signs the new CSR, and returns the active CA certificate. If the CA has been rotated, the agent should update its stored CA certificate.

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

`go/sys/` provides opinionated Linux system management utilities. All privileged operations run through `sudo`, so the calling process does not need to be root.

#### `sys/exec` — Command Execution

```go
import "github.com/manchtools/power-manage/sdk/go/sys/exec"

result, err := exec.Run(ctx, "ls", "-la")          // basic command
result, err := exec.Sudo(ctx, "systemctl", "restart", "nginx")  // with sudo
stdout, err := exec.Query("hostname")               // quick query
ok := exec.Check("which", "nginx")                  // boolean check
```

Key features:
- Streaming output via `RunStreaming` with per-line callbacks
- Automatic path resolution for sudo commands
- Output truncation at 1 MiB to prevent memory issues

#### `sys/fs` — Filesystem Operations

```go
import "github.com/manchtools/power-manage/sdk/go/sys/fs"

content, err := fs.ReadFile(ctx, "/etc/hostname")
err := fs.WriteFileAtomic(ctx, "/etc/nginx/nginx.conf", content, "0644", "root", "root")
exists := fs.FileExists(ctx, "/etc/motd")
err := fs.MkdirWithPermissions(ctx, "/opt/app", "0755", "app", "app", true)
```

All operations use sudo for privilege escalation. `WriteFileAtomic` writes to a temp file and renames for crash safety.

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

#### `sys/systemd` — Systemd Unit Management

```go
import "github.com/manchtools/power-manage/sdk/go/sys/systemd"

status := systemd.Status("nginx.service")    // {Enabled, Active, Masked, Static}
err := systemd.EnableNow(ctx, "nginx.service")
err := systemd.WriteUnit(ctx, "myapp.service", unitContent)
err := systemd.DaemonReload(ctx)
```

### Running SDK Tests

The `sys/` packages include integration tests that run inside a systemd-enabled container:

```bash
./sdk/test/run-tests.sh
```

This builds a test image, boots systemd, and runs all tests as a non-root user with sudo access.

## TypeScript SDK

Generated TypeScript types for the web frontend. The release includes a pre-built tarball of the generated files.

Generation uses [Buf](https://buf.build/) with `protoc-gen-es`:

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

## License

MIT — see [LICENSE](LICENSE).
