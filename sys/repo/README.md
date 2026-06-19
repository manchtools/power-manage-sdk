# Repository management SDK

Configure external package-manager repositories (apt, dnf, pacman, zypper)
through a single `Manager` interface built over an injected `exec.Runner` — no
global state, fully unit-testable with `exectest.FakeRunner` (no host, no sudo,
no container).

It owns the per-backend repository file format, GPG public-key import, the
idempotency comparison, conflict cleanup, and the post-configuration metadata
refresh, so a consumer never shells out to write a `.sources`/`.repo` file,
`rpm --import`, or `zypper addrepo` by hand.

## Quick start

```go
import (
    "github.com/manchtools/power-manage-sdk/pkg"
    "github.com/manchtools/power-manage-sdk/sys/exec"
    "github.com/manchtools/power-manage-sdk/sys/repo"
)

r, _ := exec.NewRunner(exec.Direct) // the agent runs as root; elsewhere Sudo/Doas
m, err := repo.New(pkg.Dnf, r)      // pkg.Apt / pkg.Dnf / pkg.Pacman / pkg.Zypper
if err != nil { /* unsupported backend (flatpak/unknown) or nil runner */ }

out, err := m.Apply(ctx, repo.Repository{Name: "corp", Dnf: &repo.DnfConfig{
    BaseURL:  "https://packages.example.com/el9",
    GPGCheck: true,
    GPGKey:   "https://packages.example.com/RPM-GPG-KEY",
    Enabled:  true,
}})
// out.Changed reports whether on-disk state actually changed (false = no-op).
// out.Result.Stdout carries a human-readable log of the steps taken.

_, err = m.Remove(ctx, "corp") // idempotent: removing an absent repo is a no-op
```

Discover which backends exist with `pkg.Detect(ctx)` — repositories belong to a
package manager, so `repo` has no separate detector. Flatpak has no native-style
repository (its remotes live on `pkg.FlatpakManager`), so `New` rejects it with
`ErrUnsupportedBackend`.

## Design notes

- **`New(backend, runner)` then `Apply`/`Remove`/`Validate`.** The backend is
  fixed at construction; set the matching sub-config on `Repository` (the shape
  mirrors the control-plane `RepositoryParams` message). `Validate` is exposed
  separately so a caller can reject a malformed configuration *before* taking any
  privileged side effect (e.g. remounting a read-only root); `Apply` re-validates
  internally regardless.

- **Privileged writes go through `fs.Manager`.** On the Direct (root) backend
  that means the TOCTOU-safe, fd-anchored write path — a hardening upgrade over a
  raw `cp`/sudo write into a world-traversable config directory.

- **GPG keys are public, not secrets.** apt receives the key material as bytes
  (`AptConfig.GPGKey`) — the caller downloads it under its own network policy —
  which the Manager dearmors (`gpg --dearmor`, key on stdin, never argv) into
  `/etc/apt/keyrings`. dnf/zypper receive a key *reference* (an https URL or
  absolute path) that the package manager itself resolves via `rpm --import`. No
  `exec.Secret` is involved.

- **Fail-closed validation.** Every repository name and string field is validated
  against a tight grammar before it can reach a config file or argv: names are
  filename/operand-safe, URLs reject control characters (dnf/pacman/zypper also
  require https; apt is exempt because its trust anchor is the signed `Release`),
  and GPG key references are restricted to https URLs or absolute paths.

- **Idempotent + change-reporting.** Apply compares against on-disk state and
  reports `Changed=false` for a no-op (skipping the metadata refresh); Remove
  reports `Changed=false` when the repository is already absent. Non-fatal steps
  (key import, index refresh) are surfaced as warnings in the output rather than
  discarding a repository that was already configured.
```
