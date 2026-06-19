# SDK documentation — authoring guide

`docs/` is the narrative documentation for the Power Manage SDK. It is served
with **open-docs** (folder tree = navigation; `NN-` prefixes order; frontmatter
sets titles) and kept honest against the code with **open-docref**
(`docref.toml` at the repo root; `docref check` runs in CI).

Don't re-derive the conventions from memory — read the canonical specs:

- **open-docs** content model, every Markdoc tag, and the gotchas:
  <https://github.com/manchtools/open-docs/blob/main/AGENTS.md>
- **open-docref** anchoring format and the check / refresh / approve workflow:
  <https://github.com/manchtools/open-docref/blob/main/AGENTS.md>

(These are deliberately referenced, not copied: a verbatim copy would drift from
the upstream spec — the exact thing docref exists to prevent.)

## SDK-specific notes

- **Content root is `docs/`.** Sections are `NN-<name>/` folders with an
  `index.md` landing page. Only `.md` files under `docs/` become pages, so keep
  non-page files (like this one) out of `docs/`.
- **Reference is generated, not hand-written.** Per-package API docs live on
  pkg.go.dev; this site is narrative — concepts, recipes, contributing. Don't
  mirror method signatures into prose.
- **Anchor Go code with docref.** A claim or snippet points at a symbol
  (`sys/<pkg>/<file>.go#Symbol`) or a marked region (`<file>.go#@name`).
  `src=` paths are relative to the repo root, where `docref.toml` lives.
- **After changing anchored code:** `docref refresh <doc>` for snippets; read
  the prose and `docref approve <doc>` for claims (never approve unread); then
  `docref check` must exit `0`.
