# Contributing to the Power Manage SDK

This SDK holds the protocol definitions (`.proto`) and shared libraries used by the Control Server, Gateway, Agent, and Web UI. Changes here ripple into every downstream component, so most contributions start by understanding where the breakage will land.

## Before you start

- **Use an issue.** For anything beyond a typo, file an issue first. The issue is where the proto shape / API surface gets agreed before code is written — it's much cheaper to revise a comment thread than a merged PR that three other repos already depend on.
- **Branch naming**: `<prefix>/issue-<number>-<short-description>`. Prefixes: `feat/`, `fix/`, `refactor/`, `docs/`, `chore/`, `test/`.
- **Commit messages**: conventional-commit prefixes (`feat:`, `fix:`, `refactor:` …). GitHub's auto-generated release notes group by these prefixes.

## Workspace layout

```
sdk/
├── proto/pm/v1/       Source of truth for every RPC and message
├── gen/               Generated Go + TypeScript code (do not edit)
├── go/                Go libraries consumed by agent + server
├── ts/                TypeScript libraries consumed by the web UI
├── docs/              Pattern guides and architectural notes
└── Makefile           Proto generation (`make generate`)
```

## Local development

```bash
# Regenerate proto bindings after editing any .proto file
make generate

# Go build + vet + test
go build ./...
go vet ./...
go test ./...

# TypeScript
cd ts && npm install && npm run build
```

Agent and server repos consume the SDK via a `replace ../sdk` directive in dev. That means any change you make here is picked up by `go build` in those checkouts immediately — if you break the Go API, their builds break too. Check both repos compile against your branch before pushing.

## Proto changes

The proto tree is the public wire format. Everything about a proto change is high-consequence.

- **Never reuse field numbers.** Even if a field is removed, don't reuse its wire number.
- **Renames are breaking changes.** Wire numbers are the API; names are the code binding. If a rename is necessary, it's a coordinated breaking change across SDK + agent + server + web in one window, not a deprecation dance. If you can't commit to landing all four in the same release, don't start the rename.
- **Default values matter.** An unset enum or bool is the zero value, so always pick the zero case to be "most common / safest." Agents built before a new enum value was added will silently see field=0 — make sure that keeps working.
- **After edits, regenerate** with `make generate` and commit both the proto and the `gen/` changes in the same commit. CI will reject mismatched state.

## Adding a pluggable capability

If the capability you're adding can be delivered by more than one tool on different distros (think sudo vs doas, systemd vs OpenRC, iptables vs nftables), follow the **backend pattern** documented in [`docs/backend-pattern.md`](docs/backend-pattern.md). Every pluggable `sys/*` package uses that exact shape — copy-paste from an existing one (e.g., `sys/service`) rather than improvising.

Short version of what "following the pattern" means:

1. A `Backend` enum in the Go package + a matching enum in the proto file.
2. An `atomic.Int32`-backed setter that **ignores unknown values** (so a zero-valued proto enum can't regress a configured agent).
3. An `ErrBackendNotSupported` sentinel for operations on unimplemented backends.
4. A Stringer for log output.
5. Per-operation dispatch (`switch CurrentBackend() {}`) in the public API; backend-specific helpers live in sibling files with the backend name appended.
6. Tests covering default, unknown-value guard, sentinel error, and Stringer.

See the pattern doc for the full template and the list of packages already using it.

## Go style

- Use `slog` for logging; never `log` or `fmt.Printf` in library code.
- Return wrapped errors (`fmt.Errorf("context: %w", err)`) — callers should be able to `errors.Is` / `errors.As` against sentinels.
- Don't silently ignore errors. At minimum log at `slog.Warn` with enough context to debug.
- No `panic` in library code. Return an error.
- `context.Context` as the first parameter for any function that performs I/O or subprocess execution.
- Privileged operations go through `sys/exec.Privileged` — not direct `os/exec`. The only exceptions are at-startup setup code that runs as root (e.g., `internal/setup` in the agent) and stdlib utility like `exec.LookPath` that doesn't actually execute anything.

## TypeScript style

- `sdk/ts/` is framework-agnostic. Don't import SvelteKit, React, or anything UI-specific here. The web repo wraps these utilities with UI-specific concerns.
- Error shapes mirror the Go error-code system (`common.proto` `ErrorDetail`). `getErrorCode(error)` extracts the structured code; downstream consumers map it to i18n keys.

## Testing

- `_test.go` files are conventional unit tests — keep them fast (<1s) and hermetic.
- Integration tests go behind the `integration` build tag and live in files named `*_test.go` with `//go:build integration` at the top. These talk to real subsystems (`systemctl`, `cryptsetup`, testcontainers' Postgres) and run in CI as a separate job.

## Release coordination

The SDK is usually released first; agent / server / web bump their SDK dependency in a follow-up PR. When a breaking SDK change lands:

1. Merge the SDK PR into `main` (this breaks downstream CI on every non-same-named branch).
2. Open and merge the corresponding downstream PRs within the same window.
3. Tag the SDK if the change is part of a versioned release. Patch releases (`vYYYY.MM.XX`) tag only the changed repo; major/minor (`vYYYY.MM`) tag all four repos.

Keep the PR's body specific about which downstream repos need migration so reviewers can check that coordination happened.

## Anti-patterns

Catalogued in [`docs/backend-pattern.md`](docs/backend-pattern.md#anti-patterns--things-not-to-do); most apply beyond just backend packages. The headline ones:

- Don't runtime-detect which tool is installed. Explicit beats clever.
- Don't build generic registries when seven copies of the same 60-line file are clearer.
- Don't use booleans where an enum fits.
- Don't rename released enum values.
- Don't swallow errors.
