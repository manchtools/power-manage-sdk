//go:build container

// Real-execution SECURITY tests for the repository Manager — the hostile
// counterpart to repo_container_test.go's happy paths. Package repo is a
// supply-chain trust boundary: a wrong configuration lets a managed host install
// attacker-controlled packages as root. The hermetic fake-runner tests in
// security_machine_test.go / validate_test.go pin these controls against scripted
// output; the tests here drive the SAME controls through the REAL package-manager
// tooling, the real `gpg --dearmor`, and the real fd-anchored filesystem, so a
// drift in any of those (a gpg exit-code change, a deb822/.repo/pacman.conf parse
// change, an fs.Manager removal-confinement regression) is caught against ground
// truth rather than a mock.
//
// Policy note: apt `Trusted: yes`, dnf `gpgcheck=0`, zypper `--no-gpgcheck`, and
// pacman `TrustAll` are documented OPERATOR CHOICES (per the 2026-06 policy, same
// as WS8) — they are NOT rejected. The "operator override" tests below PIN them as
// allowed-by-design so a future change that silently starts rejecting them is
// caught. The trust downgrade that IS refused — pacman `SigLevel Never` (signature
// verification disabled, no valid per-invocation semantics) — and the reserved
// `[options]` name are exercised as real rejections that leave the host untouched.
//
// Every lane runs as root, so the Direct runner is correct and direct os.* writes
// stand in for an attacker who has already planted conflicting config. All tests
// are Detect-gated and hermetic: no external repo is ever fetched (unreachable
// example.com URLs + parser/cacheonly probes).
package repo

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
)

// armoredTestKey2 is a SECOND throwaway ed25519 PUBLIC key (no secret committed),
// distinct from armoredTestKey, used to exercise real key ROTATION: a re-Apply
// with a different key must re-dearmor and replace the on-disk keyring.
const armoredTestKey2 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEajeV+BYJKwYBBAHaRw8BAQdAxo9qGCe3XUaNKRWUE98ne0eruTOpxaf85Jlm
Crw1INe0NVBNIFJlcG8gVGVzdCBLZXkgMiA8cmVwby10ZXN0LTJAcG93ZXItbWFu
YWdlLmludmFsaWQ+iJMEExYKADsWIQQdwrxp0Zm6NyeuKiSY6wjO212V4AUCajeV
+AIbIwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRCY6wjO212V4B/oAQDX
IzP53rgn9zz6rhzYNLf7yWtog0MbeGAjFPy5/B2G3gEAuhJEqqjp+uBXM0MvYrfc
547DbFV618I2mEz+yeMz7gI=
=CJdT
-----END PGP PUBLIC KEY BLOCK-----
`

// --- APT -------------------------------------------------------------------

// TestRepoSecurity_AptMalformedKey_Rejected_Container drives a non-PGP blob as the
// signing key. Real `gpg --dearmor` exits non-zero on garbage, so the key path
// must FAIL CLOSED: Apply returns an error and writes NEITHER the .sources NOR the
// keyring. A partial write here would leave a repo configured to fetch packages
// the host cannot verify.
func TestRepoSecurity_AptMalformedKey_Rejected_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Apt)
	ctx := repoCtx(t)
	const name = "pm-sec-apt-badkey"
	repoFile, keyFile := aptRepoFile(name), aptKeyFile(name)
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	_, err := m.Apply(ctx, Repository{Name: name, Apt: &AptConfig{
		URL:          "https://example.com/pm-sec-debian",
		Distribution: "bookworm",
		Components:   []string{"main"},
		GPGKey:       []byte("this is definitely not an OpenPGP public key"),
	}})
	if err == nil {
		t.Fatal("Apply accepted a malformed GPG key; expected real gpg --dearmor to fail the Apply closed")
	}
	if fileExists(repoFile) {
		t.Errorf("malformed-key Apply still wrote the .sources file %s — must not configure a repo whose key failed", repoFile)
	}
	if fileExists(keyFile) {
		t.Errorf("malformed-key Apply wrote a keyring %s from un-dearmorable input", keyFile)
	}
}

// TestRepoSecurity_AptConflictCleanupConfinedToKeyringJail_Container plants a
// hostile pre-existing source that references the same URL and carries two
// Signed-By targets: one inside the apt keyring jail and one OUTSIDE it (a stand-in
// for /etc/sudoers). Applying the real repo triggers conflict cleanup, which must
// remove the conflicting source and its in-jail key but REFUSE to delete the
// out-of-jail target — otherwise attacker-controlled config turns repo
// reconfiguration into an arbitrary privileged file delete. This drives the real
// fd-anchored fs.Manager removal, not a fake.
func TestRepoSecurity_AptConflictCleanupConfinedToKeyringJail_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Apt)
	ctx := repoCtx(t)
	const name = "pm-sec-apt-conflict"
	const url = "https://example.com/pm-sec-conflict"
	repoFile, keyFile := aptRepoFile(name), aptKeyFile(name)

	if err := os.MkdirAll(aptKeyringDir, 0o755); err != nil {
		t.Fatalf("prepare keyring dir: %v", err)
	}
	decoySource := aptSourcesDir + "/pm-sec-decoy.sources"
	inJailKey := aptKeyringDir + "/pm-sec-decoy-injail.gpg"
	outOfJailSentinel := "/etc/pm-sec-out-of-jail-sentinel.gpg" // NOT under any keyring dir

	for path, body := range map[string]string{
		inJailKey:         "decoy-in-jail-key\n",
		outOfJailSentinel: "do-not-delete-me\n",
		decoySource: "Types: deb\nURIs: " + url + "\nSuites: bookworm\nComponents: main\n" +
			"Signed-By: " + inJailKey + "\n" +
			"Signed-By: " + outOfJailSentinel + "\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("plant %s: %v", path, err)
		}
	}
	t.Cleanup(func() {
		_, _ = m.Remove(context.Background(), name)
		_ = os.Remove(decoySource)
		_ = os.Remove(inJailKey)
		_ = os.Remove(outOfJailSentinel)
	})

	o, err := m.Apply(ctx, Repository{Name: name, Apt: &AptConfig{
		URL: url, Distribution: "bookworm", Components: []string{"main"}, GPGKey: []byte(armoredTestKey),
	}})
	if err != nil {
		t.Fatalf("Apply(apt conflict): %v", err)
	}

	if fileExists(decoySource) {
		t.Errorf("conflicting source %s was not removed by cleanup", decoySource)
	}
	if fileExists(inJailKey) {
		t.Errorf("in-jail decoy keyring %s was not cleaned up (conflict cleanup did not run on the in-jail key)", inJailKey)
	}
	if !fileExists(outOfJailSentinel) {
		t.Errorf("SECURITY: out-of-jail Signed-By target %s was deleted — cleanup escaped the keyring jail (arbitrary privileged delete)", outOfJailSentinel)
	}
	if !strings.Contains(o.Result.Stdout, "refusing to remove out-of-jail") {
		t.Errorf("expected the log to record refusing the out-of-jail key; log:\n%s", o.Result.Stdout)
	}
	if !fileExists(repoFile) || !fileExists(keyFile) {
		t.Errorf("the new repo was not configured: source=%v key=%v", fileExists(repoFile), fileExists(keyFile))
	}
}

// TestRepoSecurity_AptKeyRotation_Container exercises the real key lifecycle: an
// initial key is dearmored and installed, a rotation to a DIFFERENT key replaces
// the on-disk keyring (Changed=true), and a re-Apply of the rotated key is an
// idempotent no-op (Changed=false). This pins updateAptKey's differ→rewrite vs
// already-installed branches against real `gpg --dearmor` output.
func TestRepoSecurity_AptKeyRotation_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Apt)
	ctx := repoCtx(t)
	const name = "pm-sec-apt-rotate"
	const url = "https://example.com/pm-sec-rotate"
	keyFile := aptKeyFile(name)
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	repoWith := func(key string) Repository {
		return Repository{Name: name, Apt: &AptConfig{
			URL: url, Distribution: "bookworm", Components: []string{"main"}, GPGKey: []byte(key),
		}}
	}

	if _, err := m.Apply(ctx, repoWith(armoredTestKey)); err != nil {
		t.Fatalf("Apply(key A): %v", err)
	}
	keyA := readFile(t, keyFile)
	if keyA == "" || strings.HasPrefix(keyA, "-----BEGIN PGP") {
		t.Fatalf("key A was not dearmored into the keyring")
	}

	o, err := m.Apply(ctx, repoWith(armoredTestKey2))
	if err != nil {
		t.Fatalf("Apply(key B rotation): %v", err)
	}
	if !o.Changed {
		t.Error("rotating to a different key should report Changed=true")
	}
	keyB := readFile(t, keyFile)
	if keyB == keyA {
		t.Error("the keyring still holds key A after rotation to key B")
	}
	if keyB == "" || strings.HasPrefix(keyB, "-----BEGIN PGP") {
		t.Error("key B was not dearmored into the keyring")
	}

	o2, err := m.Apply(ctx, repoWith(armoredTestKey2))
	if err != nil {
		t.Fatalf("re-Apply(key B): %v", err)
	}
	if o2.Changed {
		t.Error("re-applying the same rotated key should be idempotent (Changed=false)")
	}
}

// TestRepoSecurity_AptRejectedReapplyPreservesExisting_Container configures a valid
// repo, then re-applies the SAME name with an invalid configuration (a control
// character in the distribution — config injection). Apply re-validates first, so
// the rejection must happen BEFORE any side effect: the original, working .sources
// is left byte-for-byte intact. This is the "old config torn down, new config
// rejected" partial-side-effect hazard — a rejected reconfigure must never leave
// the host with no repo (or a half-written one).
func TestRepoSecurity_AptRejectedReapplyPreservesExisting_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Apt)
	ctx := repoCtx(t)
	const name = "pm-sec-apt-preserve"
	const url = "https://example.com/pm-sec-preserve"
	repoFile := aptRepoFile(name)
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	if _, err := m.Apply(ctx, Repository{Name: name, Apt: &AptConfig{
		URL: url, Distribution: "bookworm", Components: []string{"main"}, GPGKey: []byte(armoredTestKey),
	}}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	original := readFile(t, repoFile)

	_, err := m.Apply(ctx, Repository{Name: name, Apt: &AptConfig{
		URL: url, Distribution: "bookworm\nMalicious: injected", Components: []string{"main"}, GPGKey: []byte(armoredTestKey),
	}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("re-Apply with a control-char distribution: got err=%v, want ErrInvalidConfig", err)
	}
	if got := readFile(t, repoFile); got != original {
		t.Errorf("a rejected re-Apply mutated the existing .sources:\n--- before ---\n%s\n--- after ---\n%s", original, got)
	}
}

// TestRepoSecurity_AptTrustedYes_OperatorOverride_Container pins the operator
// choice: a keyless Trusted: yes repo (signature verification off) is ALLOWED by
// design and accepted by real apt. This is the fail-open hole the operator
// explicitly opted into; the test exists so a future change that starts rejecting
// it is a deliberate, visible decision — not a silent policy reversal.
func TestRepoSecurity_AptTrustedYes_OperatorOverride_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Apt)
	ctx := repoCtx(t)
	const name = "pm-sec-apt-trusted"
	const url = "https://example.com/pm-sec-trusted"
	repoFile := aptRepoFile(name)
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	if _, err := m.Apply(ctx, Repository{Name: name, Apt: &AptConfig{
		URL: url, Distribution: "bookworm", Components: []string{"main"}, Trusted: true,
	}}); err != nil {
		t.Fatalf("Apply(apt Trusted:yes) is an allowed operator override but failed: %v", err)
	}
	src := readFile(t, repoFile)
	if !strings.Contains(src, "Trusted: yes") {
		t.Errorf(".sources missing the operator-chosen Trusted: yes:\n%s", src)
	}
	if strings.Contains(src, "Signed-By:") {
		t.Errorf("keyless Trusted repo must not emit a Signed-By:\n%s", src)
	}
	if !aptParsesRepo(t, url) {
		t.Error("apt did not parse the Trusted: yes .sources")
	}
}

// --- DNF -------------------------------------------------------------------

// TestRepoSecurity_DnfGpgcheckZeroDropsKeyImport_Container pins the trust-downgrade
// guard in applyDnf: when gpgcheck is off, the gpgkey reference is DROPPED from the
// .repo and the key is NOT imported. Importing it behind gpgcheck=0 would trust the
// key system-wide while the repo verifies nothing — a silent trust downgrade. The
// written .repo carries gpgcheck=0 with no gpgkey= line, and real dnf parses it.
func TestRepoSecurity_DnfGpgcheckZeroDropsKeyImport_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Dnf)
	ctx := repoCtx(t)
	const name = "pm-sec-dnf-nokey"
	repoFile := dnfRepoFile(name)
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	if _, err := m.Apply(ctx, Repository{Name: name, Dnf: &DnfConfig{
		BaseURL: "https://example.com/pm-sec-el9", Description: "PM Sec", Enabled: true,
		GPGCheck: false, GPGKey: "https://example.com/pm-sec-el9/RPM-GPG-KEY",
	}}); err != nil {
		t.Fatalf("Apply(dnf gpgcheck=0): %v", err)
	}
	body := readFile(t, repoFile)
	if !strings.Contains(body, "gpgcheck=0") {
		t.Errorf(".repo missing gpgcheck=0:\n%s", body)
	}
	if strings.Contains(body, "gpgkey=") {
		t.Errorf("SECURITY: gpgkey= was written behind gpgcheck=0 — the key would be trusted while the repo verifies nothing:\n%s", body)
	}
	if !dnfListsRepo(name) {
		t.Errorf("dnf did not list %q after Apply", name)
	}
}

// --- PACMAN ----------------------------------------------------------------

// TestRepoSecurity_PacmanSigLevelNever_Rejected_Container drives the one pacman
// trust downgrade that IS refused: SigLevel "Never" disables signature
// verification, so the repo would install unsigned/forged packages. Apply must
// reject it before writing, leaving /etc/pacman.conf untouched (no [section]).
func TestRepoSecurity_PacmanSigLevelNever_Rejected_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Pacman)
	ctx := repoCtx(t)
	const name = "pm-sec-pacman-never"
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	before := readFile(t, pacmanConf)
	_, err := m.Apply(ctx, Repository{Name: name, Pacman: &PacmanConfig{
		Server: "https://example.com/pm-sec-arch/$repo/os/$arch", SigLevel: "Never",
	}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Apply(SigLevel Never): got err=%v, want ErrInvalidConfig", err)
	}
	if after := readFile(t, pacmanConf); after != before {
		t.Errorf("a rejected SigLevel Never still mutated /etc/pacman.conf")
	}
	if strings.Contains(readFile(t, pacmanConf), "["+name+"]") {
		t.Errorf("pacman.conf gained a [%s] section despite the rejection", name)
	}
}

// TestRepoSecurity_PacmanReservedOptionsName_Rejected_Container ensures a repo
// named "options" is refused: its [options] header would collide with pacman.conf's
// global settings block and silently rewrite system-wide configuration. The real
// /etc/pacman.conf (which has a genuine [options] block) must be left untouched.
func TestRepoSecurity_PacmanReservedOptionsName_Rejected_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Pacman)
	ctx := repoCtx(t)

	before := readFile(t, pacmanConf)
	_, err := m.Apply(ctx, Repository{Name: "options", Pacman: &PacmanConfig{
		Server: "https://example.com/pm-sec-arch/$repo/os/$arch",
	}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Apply(name=options): got err=%v, want ErrInvalidConfig", err)
	}
	if after := readFile(t, pacmanConf); after != before {
		t.Error("a rejected reserved-name Apply mutated the global pacman.conf [options] block")
	}
}

// TestRepoSecurity_PacmanTrustAll_OperatorOverride_Container pins the operator
// choice: "Optional TrustAll" relaxes the trust DB but still requires a valid
// signature, so it is allowed (unlike Never). Real pacman accepts the section.
func TestRepoSecurity_PacmanTrustAll_OperatorOverride_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Pacman)
	ctx := repoCtx(t)
	const name = "pm-sec-pacman-trustall"
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	if _, err := m.Apply(ctx, Repository{Name: name, Pacman: &PacmanConfig{
		Server: "https://example.com/pm-sec-arch/$repo/os/$arch", SigLevel: "Optional TrustAll",
	}}); err != nil {
		t.Fatalf("Apply(Optional TrustAll) is an allowed operator override but failed: %v", err)
	}
	if !pacmanParsesRepo(name) {
		t.Errorf("`pacman-conf --repo %s` failed — pacman did not accept the TrustAll section", name)
	}
}

// --- ZYPPER ----------------------------------------------------------------

// TestRepoSecurity_ZypperNoGpgcheck_OperatorOverride_Container pins the operator
// choice: GPGCheck=false adds `--no-gpgcheck`, an allowed-by-design downgrade. Real
// zypper registers the alias; the test exists so a future change that rejects it is
// a deliberate decision, not a silent reversal.
func TestRepoSecurity_ZypperNoGpgcheck_OperatorOverride_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Zypper)
	ctx := repoCtx(t)
	const name = "pm-sec-zypper-nogpg"
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	if _, err := m.Apply(ctx, Repository{Name: name, Zypper: &ZypperConfig{
		URL: "https://example.com/pm-sec-suite", Description: "PM Sec", Enabled: false,
		Autorefresh: false, GPGCheck: false,
	}}); err != nil {
		t.Fatalf("Apply(zypper --no-gpgcheck) is an allowed operator override but failed: %v", err)
	}
	if !zypperRepoListed(t, name) {
		t.Errorf("`zypper lr %s` does not list the repo after the operator-override Apply", name)
	}
}
