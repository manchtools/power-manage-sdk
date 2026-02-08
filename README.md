# Power Manage SDK

Shared protocol definitions, generated code, and client libraries for Power Manage. Used by the [Control Server](../server/cmd/control/), [Gateway](../server/cmd/gateway/), [Agent](../agent/), and [Web UI](../web/).

## Contents

```
sdk/
├── proto/pm/v1/           Protocol Buffer source definitions
│   ├── common.proto         Base types, enums, identifiers
│   ├── actions.proto        Action types, parameters, scheduling
│   ├── agent.proto          Bidirectional streaming (Agent ↔ Gateway)
│   └── control.proto        Control API (50+ RPCs)
│
├── gen/go/pm/v1/           Generated Go code (protobuf + Connect RPC)
│   ├── *.pb.go               Message types with injected validation tags
│   └── pmv1connect/          Connect RPC client and server interfaces
│
├── go/
│   ├── client.go            Agent streaming client (mTLS, heartbeat, action dispatch)
│   └── pkg/                 Package manager abstraction library
│       ├── apt.go             APT (Debian/Ubuntu)
│       ├── dnf.go             DNF (Fedora/RHEL)
│       ├── pacman.go          Pacman (Arch Linux)
│       ├── zypper.go          Zypper (openSUSE)
│       └── flatpak.go         Flatpak (cross-distro)
│
└── Makefile                Proto generation commands
```

## Proto Definitions

Four proto files define the entire API surface:

| File | Purpose |
|------|---------|
| `common.proto` | ULID identifiers, execution status, assignment modes |
| `actions.proto` | 15 action types (package, update, repository, app_image, deb, rpm, flatpak, shell, systemd, file, directory, reboot, sync, user), parameters, scheduling |
| `agent.proto` | `AgentService` — bidirectional streaming RPC + action sync, heartbeat, output streaming, OS queries |
| `control.proto` | `ControlService` — 50+ RPCs for users, devices, groups, actions, sets, definitions, assignments, tokens, executions |

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

### Package Manager Library

`go/pkg/` abstracts five Linux package managers behind a unified interface with a builder API:

```go
import "github.com/manchtools/power-manage/sdk/go/pkg"

pm, _ := pkg.New()                          // auto-detect
pm.Install("nginx").Version("1.24.0").Run() // fluent builder
updates, _ := pm.ListUpgradable()           // query methods
```

See the [package manager README](go/pkg/README.md) for the full API.

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
