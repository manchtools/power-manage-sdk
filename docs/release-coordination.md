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
    github.com/manchtools/power-manage/sdk v0.0.0-20260411192158-80326c39d5aa
    // ...
)

replace github.com/manchtools/power-manage/sdk => github.com/manchtools/power-manage-sdk v0.0.0-20260411192158-80326c39d5aa
```

Two things of note:

1. The version is a Go pseudo-version (`v0.0.0-TIMESTAMP-SHORTSHA`),
   which Go accepts even without a matching tag.
2. The `replace` directive maps the in-repo import path
   (`github.com/manchtools/power-manage/sdk`) to the actual GitHub repo
   URL (`github.com/manchtools/power-manage-sdk`), because the module
   was laid out as monorepo-style imports on a polyrepo-style git
   layout. Without the replace, `go get` can't find the repo.

`go build` fetches the pinned commit from GitHub. Nothing looks at SDK
main unless someone explicitly bumps the pin.

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

The SDK's existing `vYYYY.MM.XX` tags (e.g. `v2026.04.03`) are used as
human-readable release labels — they show up in GitHub Releases and
help operators pick versions for deployment. They are NOT valid Go
module versions (Go requires semver, `v0.x.x` or `v1.x.x`), so
downstream `go.mod` doesn't reference them.

Two separate identities:

| Identity | Format | Used by |
|---|---|---|
| Human-readable release tag | `v2026.04.03`, `v2026.05-rc1` | GitHub Releases, operator-facing docs |
| Go module pin | `v0.0.0-TIMESTAMP-SHORTSHA` (pseudo-version) | agent/server go.mod |

Both can live at the same commit. The release workflow
(`.github/workflows/release.yml`) fires on any tag matching `v*` and
builds TypeScript SDK assets for the GitHub Release page.

If at some point you want actual semver Go tags (to use nicer-looking
pins like `v1.0.0` instead of pseudo-versions), that's a future
decision — starting a `v1.x.x` line would be additive to the existing
calendar-versioned tags, not a replacement.

## Anti-patterns

- **Don't delete old tags.** Downstream may still pin to them.
- **Don't push `v0.x.x` or `v1.x.x` style tags** unless you're ready to
  commit to Go module semver discipline (can't go back). Stick with
  pseudo-versions until that's an intentional move.
- **Don't skip the `go.work` for cross-cutting dev.** Editing the
  pseudo-version by hand with a fake SHA sometimes works, sometimes
  doesn't, and always confuses other developers. `go.work` is what it
  exists for.
- **Don't put `go.work` in any repo's git history.** It's workspace-
  local by design.
