# SDK test methodology

The SDK wraps privileged, distro-specific host tooling (package managers, repo
config, trust stores, systemd, firewall, LUKS, …) and runs it as **root on a
fleet** with input from a semi-trusted control plane. That threat + portability
profile — not "it's just CLI arg wrappers" — is what dictates how we test.

## Tiering: test rigor follows risk

Every capability is classified by one discriminator:

> **Does it take untrusted input AND act with privilege?**

| Tier | Profile | Required testing |
|------|---------|------------------|
| **A — trust boundary** | untrusted input × privileged (repo, pkg, catrust, service unit content, dns, luks, remote download) | Full rejection coverage (correct / absent / malformed, driven through the real handler) · real-tool container tests · fitness functions (`archtest/`) |
| **B — privileged, fixed input** | runs as root but args are operator/code-controlled, no untrusted data | Happy-path + idempotency + a couple of rejection tests; **no** adversarial state machine |
| **C — pure helper** | no privilege, no untrusted input | Ordinary unit tests |

Only Tier-A gets the adversarial state machines (`*security_machine_test.go`,
`adversary/`) and the Turso-style DST harness (`adversary/dst_test.go`, one
module-level harness — never replicated per package). This caps the maintenance
cost and concentrates effort where a bug means root RCE on the fleet.

## Two execution levels (aligned with Ansible/Chef/Puppet)

Config-management tooling (Molecule, Test Kitchen, rspec-puppet) splits the same
way, and we match it:

1. **Hermetic unit tests** — drive the capability through a `FakeRunner` with
   scripted tool output. Fast, run everywhere, pin the emitted argv / branch
   logic / declared intent without touching the host. (≈ ChefSpec / rspec-puppet
   "the catalog *would* contain X".)
2. **Real-execution container tests** (`//go:build container`) — run the REAL
   tool, real filesystem, real `gpg`/`openssl`/`cryptsetup` inside a container.
   (≈ Test Kitchen / Molecule converge.)

Three disciplines carried over from that ecosystem:

- **Idempotency is first-class** — Apply twice; the second run reports
  `Changed=false`. Asserted in every Apply/Remove container test.
- **Verify with an independent probe** — never trust "the tool says it did X";
  assert the system *is* in state X via a separate checker: `apt-get --print-uris`
  / `pacman-conf --repo` / `zypper lr` for repos, `openssl verify` for the trust
  store. (≈ ServerSpec / InSpec / testinfra.)
- **No vacuous skip** — a container cell asserts its expected tools are present at
  build/CI time, so a test never silently skips because a tool went missing.

## Distro matrix

Container tests run across the distro families a managed fleet actually runs —
the "platforms" model (Molecule platforms / Kitchen). Coverage is **empirical**:
we run every capability on every distro and let the failures define the work,
rather than predicting from code.

| Capability | Debian | Fedora | EL (Alma/Rocky) | Arch | openSUSE |
|------------|:--:|:--:|:--:|:--:|:--:|
| pkg, repo, encryption, firewall, netconfig, terminal, smart, reboot, desktop, inventory | ✅ | ✅ | ✅ | ✅ | ✅ |
| catrust | ✅ ca-certificates | ✅ p11-kit | ✅ p11-kit | ✅ p11-kit | ✅ suse-ca-certificates |
| antivirus | ✅ | ✅ | ✅ | ✅ | ✅ |
| notify (`wall`) | ✅ | ✅ | ✅ | ✅ | ❌¹ |
| osquery | ✅ | —² | —² | —² | —² |

¹ openSUSE does not package `wall` (`rpm -qf /usr/bin/wall` → absent), so the
notify broadcast path cannot run there.

² osquery is a single statically-built binary; `osqueryi --json` behaves
identically on every distro, so it is covered once on Debian (the upstream .deb).
Its rpm/AUR packaging elsewhere is fragile in CI and buys no behavioural coverage.

These two are the documented matrix gaps; everything else runs on all five families.

Each distro has a `test/Dockerfile.<distro>` (same multi-stage shape; the Go
toolchain is copied from the canonical `golang` image so the compiler is
identical everywhere and only the distro userland differs). Adding **Rocky** is a
one-line copy of `Dockerfile.almalinux` + a matrix entry — they are bug-for-bug
RHEL rebuilds, so one EL representative covers both.

### Cross-distro findings the matrix surfaced

Running the matrix (rather than scanning code) found real portability gaps that
debian-only testing hid:

- **catrust**: openSUSE ships `update-ca-certificates` (same name as Debian) but
  reads `/etc/pki/trust/anchors` → needed a dedicated `SuseCaCertificates` backend
  and a Detect that disambiguates by anchors dir. It also gave the P11Kit backend
  its first real coverage (the old debian-only test silently skipped it).
- **desktop**: openSUSE's `login.defs ALWAYS_SET_PATH` resets PATH inside
  `runuser`'s PAM session → `RunAsCommand` now re-applies the curated PATH via an
  `env PATH=…` wrapper that runs after the session is set up.
- **inventory**: the os-release test hardcoded `ID=="debian"`; generalized to
  independently read `/etc/os-release` and assert the parser agrees.

## Commands

```bash
go test ./...                                    # hermetic unit tests
go test -tags=container -run Container ./sys/... # real-execution (inside a container)
PM_DST_SEED=1 PM_DST_ITERS=20000 go test ./adversary/ -run TestDST   # DST sweep
```
