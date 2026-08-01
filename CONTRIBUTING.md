# Contributing to the Power Manage SDK

The SDK contains the shared contract and reusable mechanism layer. The sole
system-design authority is
[`../DESIGN_2026_07_31/00_TARGET_DESIGN.md`](../DESIGN_2026_07_31/00_TARGET_DESIGN.md).
Do not add compatibility shims, speculative protocol fields, or product policy
that is absent from that design.

## Workflow

Use a focused branch and small commits. For a behavior or contract change:

1. State the acceptance behavior in a test.
2. Make the smallest implementation change that passes it.
3. Regenerate checked-in bindings when protobuf changes.
4. Verify the SDK and every local consumer affected by the change.

Breaking contract changes are expected during pre-alpha consolidation. Change
the SDK, server, agent, and web together instead of maintaining old and new
paths in parallel.

## Layout

| Path | Purpose |
|------|---------|
| `proto/powermanage/v1/` | Protobuf source |
| `gen/go/powermanage/v1/` | Generated Go bindings |
| `gen/ts/powermanage/v1/` | Generated TypeScript bindings |
| `client.go` | Agent stream client |
| `crypto/`, `sys/`, `pkg/` | Reusable Go mechanisms |
| `ts/` | Framework-independent browser SDK |
| `docs/` | Mechanism and contributor documentation |

## Contract changes

- Never hand-edit `gen/`.
- Do not reuse removed field numbers.
- Keep `AgentService` to its single `Stream` method.
- Do not add local password/TOTP, Gateway, CRL-distribution, application-frame
  signing, or parallel agent transport paths.
- Mark every secret protobuf field with `debug_redact` and carry it as a
  `SealedValue`.
- Do not expose an implementation selector until more than one implementation
  actually exists and is supported end to end.
- Update the exact current RPC golden only for an explicitly approved RPC
  change. Keep predecessor deletion evidence separate.

After editing protobuf:

```bash
npm ci
make generate
```

Commit the source and generated outputs together.

## Go and TypeScript

- Accept `context.Context` first for I/O and subprocess work.
- Return wrapped, matchable errors; do not swallow failures or panic in library
  code.
- Validate deserialized and caller-controlled data before use.
- Keep secret values out of arguments, logs, errors, and formatted protobufs.
- Keep `ts/` framework-independent; Svelte-specific behavior belongs in web.
- Prefer concrete standard-library or platform mechanisms over new abstraction
  layers and dependencies.

## Verification

The canonical gate is:

```bash
./scripts/verify.sh
```

It runs the standalone SDK build with `GOWORK=off`, plus static analysis, tests,
Buf checks, docref, generated-code drift, and TypeScript checks. For a coordinated
local contract change, also run the server and agent suites from the workspace
root and the web typecheck/tests against `../sdk/gen/ts`.

See
[`docs/04-contributing/01-release-coordination.md`](docs/04-contributing/01-release-coordination.md)
for publishing the SDK commit before updating downstream module pins.
