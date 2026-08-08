# Power Manage SDK

Shared protobuf contract, generated Go and TypeScript code, agent stream client,
and reusable device capability libraries for Power Manage.

The only system-design authority is
[`../DESIGN_2026_07_31/00_TARGET_DESIGN.md`](../DESIGN_2026_07_31/00_TARGET_DESIGN.md).
This README describes how to work with the SDK repository; it does not define a
second architecture.

## Runtime contract

- Protobuf sources live in `proto/powermanage/v1/` under package
  `powermanage.v1`.
- Generated Go and TypeScript packages live in `gen/go/powermanage/v1/` and
  `gen/ts/powermanage/v1/`.
- `AgentService` exposes one bidirectional `Stream`. Handshake, synchronization,
  heartbeats, manifest delivery and receipts, results, secret operations, and
  terminal traffic are frames on that stream.
- Agent certificates authenticate the direct mTLS connection. Application
  frames are not separately signed.
- Fields classified as secret use the versioned X25519 `SealedValue` envelope
  with context-bound associated data.
- Human authentication is OIDC-based; the contract has no local password or
  TOTP RPCs.
- The exact current RPC set is pinned by `testdata/rpc_golden.json`. The separate
  predecessor golden exists only to prove the approved deletion sets; it is not
  a compatibility surface.

## Repository layout

| Path | Purpose |
|------|---------|
| `proto/powermanage/v1/` | Contract source |
| `gen/go/powermanage/v1/` | Generated protobuf and Connect Go packages |
| `gen/ts/powermanage/v1/` | Generated TypeScript messages |
| `cmd/powermanage/` | Operator CLI for bootstrap, OIDC login, and named control RPCs |
| `client.go` | Agent-side stream client and correlated stream operations |
| `crypto/` | Enrollment CSR and transport-field sealing helpers |
| `sys/` | Device capability implementations |
| `pkg/` | Package-manager capabilities |
| `ts/` | Browser client, auth storage, errors, logging, and exports |
| `docs/` | Capability and contributor documentation |

The shipped device implementations are concrete: systemd for service actions
and LUKS for disk-encryption actions. The public action contract does not expose
selectors for unimplemented alternatives. Optional forward capability packages
remain isolated until production code deliberately adopts them.

## Generate the contract

Install the lockfile-pinned JavaScript tools, then regenerate both languages:

```bash
npm ci
make generate
```

`make generate` runs protobuf generation, injects Go validation tags, formats
the Go output, and generates TypeScript with the same pinned Buf tool used by
CI. Generated files are committed.

## Verify

Run the canonical standalone-module gate:

```bash
./scripts/verify.sh
```

It checks formatting, build, vet, static analysis, Go tests, Buf lint and format,
docref, generated-code drift, TypeScript typechecking, and TypeScript tests.
`GOWORK=off` is intentional so the result matches a standalone SDK checkout.

Useful focused commands:

```bash
env GOWORK=off go test ./...
npm run typecheck
npm test
npm run lint:proto
npm run format:proto
docref check
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution mechanics and
[`docs/04-contributing/01-release-coordination.md`](docs/04-contributing/01-release-coordination.md)
for coordinated SDK/server/agent publication.
