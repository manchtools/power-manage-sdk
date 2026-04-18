# Release coordination

This document explains how SDK changes propagate to downstream repos
(agent, server, web) without the old "break everything at merge time"
failure mode.

## The problem it solves

Until recently every downstream Go consumer pinned the SDK to a
placeholder `v0.0.0` with a `replace github.com/manchtools/power-manage/sdk => ../sdk`
directive. CI rewrote the replace to point at SDK `main`. That meant
the moment a breaking SDK change landed on main, every open PR across
agent and server that didn't have a same-named SDK branch broke
immediately — the `replace` picked up the new API, the old agent/server
source no longer compiled, and you'd see red CI on a PR that hadn't
changed since yesterday.

The fix is to make downstream builds pin a *specific* SDK commit or
tag, so SDK main can move freely and downstream bumps are explicit.

## How it works now

### Downstream pinning

Agent and server `go.mod` look like this:

```go
require (
    github.com/manchtools/power-manage/sdk v0.1.0
    // ...
)

replace github.com/manchtools/power-manage/sdk => github.com/manchtools/power-manage-sdk v0.1.0
```

Two things of note:

1. The version is a proper Go-compatible semver tag (`v0.x.x` or
   `v1.x.x`). Pseudo-versions (`v0.0.0-TIMESTAMP-SHORTSHA`) are also
   accepted when you need to pin an untagged commit, but prefer a
   tagged release whenever one exists — `go.mod` stays readable.
2. The `replace` directive maps the in-repo import path
   (`github.com/manchtools/power-manage/sdk`) to the actual GitHub repo
   URL (`github.com/manchtools/power-manage-sdk`), because the module
   was laid out as monorepo-style imports on a polyrepo-style git
   layout. Without the replace, `go get` can't find the repo.

`go build` fetches the pinned version from GitHub. Nothing looks at
SDK main unless someone explicitly bumps the pin.

### Bumping the pin

Downstream repos bump the SDK pin with a normal PR:

```bash
cd agent   # or server
go get github.com/manchtools/power-manage-sdk@<commit-or-tag>
go mod tidy
git add go.mod go.sum
git commit -m "chore: bump SDK to <commit-or-tag>"
```

That PR runs CI against the new SDK commit. If it passes, merge it. If
the new SDK has breaking API changes, the same PR carries the downstream
migration.

### Cross-cutting development

When you're iterating on an SDK change and the matching agent or server
migration at the same time, pinning gets in the way. Fix: use a Go
workspace (`go.work`) at the parent directory that contains all the
repo checkouts. `go.work` overrides `replace` directives.

```bash
# At the workspace root (e.g., ~/code/power-manage/):
cat > go.work <<'EOF'
go 1.25

use (
    ./sdk
    ./agent
    ./server
)
EOF
```

Don't commit `go.work` to any repo — each developer manages their own.

When you're done with cross-cutting work, rename it to `go.work.off` (or
delete it) so regular builds go back to the pinned SDK.

## The release flow

### For SDK contributors

1. Open a PR against SDK main (small, focused — breaking changes are a
   judgment call but prefer landing them separately from additive work).
2. Merge. SDK main advances.
3. Downstream repos are *not* broken by this. They still pin the
   previous SDK commit until someone opens a bump PR.
4. Optionally tag a release (see below). Tagging is a strictly
   optional step for human-readable release names — Go pinning works
   fine against any commit.

### For agent / server maintainers

When ready to consume the latest SDK:

1. `go get github.com/manchtools/power-manage-sdk@main` (or a specific
   commit / tag) in agent or server.
2. `go mod tidy`.
3. Fix any API breakage in the same PR. Run tests.
4. Merge. Now the downstream is on the new SDK.

### Breaking-change coordination

When an SDK change is known to break downstream, the PR description
should:

1. Link the downstream migration PRs that consume the breaking change.
2. State the order of merges: SDK merges first (now the new API is
   available as a pseudo-version), then each downstream's bump PR is
   rebased on main and merged.

There's no hard coupling — the downstream migration PR stays on an old
SDK pin until its author explicitly bumps it. Missing the coordination
window just delays the migration, it doesn't break anything.

## Tags and GitHub Releases

The SDK uses two kinds of tags side-by-side:

| Identity | Format | Used by |
|---|---|---|
| Go module tag | `v0.x.x` semver | agent/server `go.mod` |
| Human-readable release label | `vYYYY.MM.XX` calendar date (e.g. `v2026.04.03`) | GitHub Releases UI, operator-facing docs |

Both can live at the same commit — the release workflow
(`.github/workflows/release.yml`) fires on any tag matching `v*` and
builds TypeScript SDK assets for the GitHub Release page regardless of
the format. They're just two ways to reference the same release.

### Why two conventions

Go modules applies **Semantic Import Versioning**: for major version
≥ 2, the import path must carry a `/vN` suffix (e.g.
`github.com/foo/bar/v2`). Calendar-style tags like `v2026.x.x` would
require renaming the SDK's import path to
`github.com/manchtools/power-manage-sdk/v2026`, which ripples into
every downstream `import` statement and has to be redone every January.
That's a high price for a version-number aesthetic.

The SDK sidesteps it by staying in the `v0.x.x` / `v1.x.x` range for
Go pinning while keeping calendar-dated GitHub Release names for
humans. Both coexist at the same commit; downstream machinery reads
the semver tag, release notes reference the calendar one.

### The pre-v1.0.0 contract

The SDK is currently on a `v0.x.x` line, which per semver means the
API is not yet stable. **Minor bumps (`v0.1.0` → `v0.2.0`) may carry
breaking changes.** Expect each bump to ship with migration notes in
the release body, and for downstream bump PRs to absorb the required
API edits in the same commit.

A move to `v1.x.x` is a deliberate decision to freeze the public
surface. Don't tag `v1.0.0` until the API has settled — once it's
cut, breaking changes become a coordinated `v2.x.x` move with a new
import path.

### Pseudo-versions

Pseudo-versions (`v0.0.0-TIMESTAMP-SHORTSHA`) remain valid for pinning
untagged commits. Use them when you need to reference a specific
commit that doesn't have a matching release tag — generally during
active cross-cutting development before the SDK side cuts its tag.
Prefer a real tag once one exists; `go.mod` readability matters.

## Anti-patterns

- **Don't delete old tags.** Downstream may still pin to them.
- **Don't tag `v1.0.0` prematurely.** Once the `v1.x.x` line is
  cut, the API is frozen; breaking changes require moving to
  `v2.x.x` and renaming the import path. Stay on `v0.x.x` until the
  public surface is genuinely stable.
- **Don't tag `v2.x.x` without renaming the import path.** Go's
  Semantic Import Versioning requires a `/v2` suffix in the path,
  and skipping it produces invalid modules that downstream can't
  pin at all.
- **Don't edit pseudo-version timestamps by hand.** Always let
  `go get @<sha-or-tag>` compute them. Hand-edited timestamps drift
  from the actual commit time and Go rejects the module.
- **Don't skip the `go.work` for cross-cutting dev.** Tweaking the
  pin to a fake SHA sometimes works, sometimes doesn't, and always
  confuses other developers. `go.work` is the right tool.
- **Don't put `go.work` in any repo's git history.** It's workspace-
  local by design.
