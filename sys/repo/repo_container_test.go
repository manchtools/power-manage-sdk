//go:build container

// Container-based real-execution tests for the repository Manager. The
// hermetic FakeRunner tests cover every branch with scripted output; these run
// the REAL Apply/Remove side effects inside a container against the actual
// package-manager tooling and filesystem, so a deb822/.repo/pacman.conf format
// change, a real `gpg --dearmor` shape change, or a zypper addrepo/removerepo
// contract change is caught here.
//
// One file, four backends, each Detect-gated: the apt cell runs in the
// container-tests matrix (Debian base + gnupg); the dnf/pacman/zypper cells run
// in their distro CI jobs (Fedora/Arch/openSUSE) which invoke this with
// `-tags=container`. Every lane runs as root, so the Direct runner is correct
// (Escalate is a no-op wrapper over the already-root process). Mutating tests
// are gated behind `//go:build container` so a plain `go test ./...` on a
// developer's real machine never touches their /etc.
package repo

import (
	"context"
	"os"
	osexec "os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// armoredTestKey is a throwaway ed25519 PUBLIC key (no secret committed) used to
// exercise the real `gpg --dearmor` + keyring-write path for apt.
const armoredTestKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEajZ3rBYJKwYBBAHaRw8BAQdAwYnGPZg6OfGisPl+/RAOseXCejyrS+CjiSKZ
lCXoDjG0MVBNIFJlcG8gVGVzdCBLZXkgPHJlcG8tdGVzdEBwb3dlci1tYW5hZ2Uu
aW52YWxpZD6IkAQTFggAOBYhBN1Qn9dyeqU4SntfyL6U56IHNSDTBQJqNnesAhsj
BQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEL6U56IHNSDTGp4BALFRj253kOzs
gxVpo/34NPKJga6Orty0loT/fCuEIwhvAQCpfGCUcX2QgqDXxrlS9IQ6wn6JCPNw
fGAUk8ja+rIzBA==
=8ls7
-----END PGP PUBLIC KEY BLOCK-----
`

func realRepoMgr(t *testing.T, b pkg.Backend) Manager {
	t.Helper()
	if !slices.Contains(pkg.Detect(context.Background()), b) {
		t.Skipf("%s not installed here; repo backend not exercisable", b)
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := New(b, r)
	if err != nil {
		t.Fatalf("New(%s): %v", b, err)
	}
	return m
}

func repoCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestApt_ApplyRemove_Container drives the real apt path end-to-end: dearmor a
// public key into /etc/apt/keyrings, write the deb822 .sources with Signed-By,
// prove idempotency, then remove both. Pins the deb822 format + real gpg dearmor.
func TestApt_ApplyRemove_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Apt)
	ctx := repoCtx(t)
	const name = "pm-test-apt"
	repoFile, keyFile := aptRepoFile(name), aptKeyFile(name)
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	repo := Repository{Name: name, Apt: &AptConfig{
		URL:          "https://example.com/pm-test-debian",
		Distribution: "bookworm",
		Components:   []string{"main"},
		GPGKey:       []byte(armoredTestKey),
	}}

	o, err := m.Apply(ctx, repo)
	if err != nil {
		t.Fatalf("Apply(apt): %v", err)
	}
	if !o.Changed {
		t.Error("first Apply should report Changed=true")
	}

	src := readFile(t, repoFile)
	for _, want := range []string{"Types: deb", "URIs: https://example.com/pm-test-debian", "Suites: bookworm", "Components: main", "Signed-By: " + keyFile} {
		if !strings.Contains(src, want) {
			t.Errorf("deb822 source missing %q:\n%s", want, src)
		}
	}
	key := readFile(t, keyFile)
	if key == "" {
		t.Error("keyring is empty")
	}
	if strings.HasPrefix(key, "-----BEGIN PGP") {
		t.Error("keyring is still ASCII-armored — real `gpg --dearmor` did not run")
	}

	// Independent tool-acceptance probe (mirrors zypperRepoListed): apt itself
	// must PARSE the written .sources. `apt-get --print-uris update` parses every
	// configured source and prints the URIs it WOULD fetch WITHOUT fetching, so
	// the repo URI appearing proves the deb822 file is well-formed and accepted —
	// not merely that the bytes we wrote back match. It does not depend on the
	// unreachable example.com metadata.
	if !aptParsesRepo(t, "https://example.com/pm-test-debian") {
		t.Error("apt did not parse the written .sources (`apt-get --print-uris update` omits the repo URI)")
	}

	// Idempotency: a second identical Apply changes nothing.
	o2, err := m.Apply(ctx, repo)
	if err != nil {
		t.Fatalf("re-Apply(apt): %v", err)
	}
	if o2.Changed {
		t.Error("idempotent re-Apply should report Changed=false")
	}

	o3, err := m.Remove(ctx, name)
	if err != nil {
		t.Fatalf("Remove(apt): %v", err)
	}
	if !o3.Changed {
		t.Error("Remove of a present repo should report Changed=true")
	}
	if fileExists(repoFile) || fileExists(keyFile) {
		t.Errorf("Remove left files behind: source=%v key=%v", fileExists(repoFile), fileExists(keyFile))
	}
	o4, err := m.Remove(ctx, name)
	if err != nil {
		t.Fatalf("re-Remove(apt): %v", err)
	}
	if o4.Changed {
		t.Error("Remove of an absent repo should report Changed=false")
	}
}

// TestDnf_ApplyRemove_Container pins the .repo INI format written to
// /etc/yum.repos.d against real dnf (the makecache refresh against the unreachable
// URL is non-fatal by design).
func TestDnf_ApplyRemove_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Dnf)
	ctx := repoCtx(t)
	const name = "pm-test-dnf"
	repoFile := dnfRepoFile(name)
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	// Happy path is a SIGNED, gpg-checked repo (the secure default). The insecure
	// gpgcheck=0 operator override is exercised separately in
	// repo_security_container_test.go so it is never modelled as the normal case.
	repo := Repository{Name: name, Dnf: &DnfConfig{
		BaseURL: "https://example.com/pm-test-el9", Description: "PM Test", Enabled: true,
		GPGCheck: true, GPGKey: "https://example.com/pm-test-el9/RPM-GPG-KEY",
	}}

	o, err := m.Apply(ctx, repo)
	if err != nil {
		t.Fatalf("Apply(dnf): %v", err)
	}
	if !o.Changed {
		t.Error("first Apply should report Changed=true")
	}
	body := readFile(t, repoFile)
	for _, want := range []string{"[" + name + "]", "name=PM Test", "baseurl=https://example.com/pm-test-el9", "enabled=1", "gpgcheck=1", "gpgkey=https://example.com/pm-test-el9/RPM-GPG-KEY"} {
		if !strings.Contains(body, want) {
			t.Errorf(".repo missing %q:\n%s", want, body)
		}
	}
	// Independent tool-acceptance probe: dnf must PARSE the written .repo.
	// `dnf repolist --all -C` lists configured repos cacheonly (no network refresh
	// against the unreachable baseurl), so the repo id appearing proves dnf
	// accepted the file, not merely that the bytes match.
	if !dnfListsRepo(name) {
		t.Errorf("dnf did not list %q after Apply (`dnf repolist --all -C` omits it) — config not accepted", name)
	}
	if o2, err := m.Apply(ctx, repo); err != nil || o2.Changed {
		t.Errorf("idempotent re-Apply: changed=%v err=%v", o2.Changed, err)
	}
	if o3, err := m.Remove(ctx, name); err != nil || !o3.Changed || fileExists(repoFile) {
		t.Errorf("Remove: changed=%v err=%v exists=%v", o3.Changed, err, fileExists(repoFile))
	}
	if o4, err := m.Remove(ctx, name); err != nil || o4.Changed {
		t.Errorf("idempotent Remove: changed=%v err=%v", o4.Changed, err)
	}
}

// TestPacman_ApplyRemove_Container pins the [section] appended to the real
// /etc/pacman.conf (the `pacman -Sy` against the unreachable Server is non-fatal).
func TestPacman_ApplyRemove_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Pacman)
	ctx := repoCtx(t)
	const name = "pm-test-pacman"
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	// Happy path requires a valid signature (the secure default). The TrustAll
	// operator override is pinned separately in repo_security_container_test.go.
	repo := Repository{Name: name, Pacman: &PacmanConfig{
		Server: "https://example.com/pm-test-arch/$repo/os/$arch", SigLevel: "Required DatabaseOptional",
	}}

	o, err := m.Apply(ctx, repo)
	if err != nil {
		t.Fatalf("Apply(pacman): %v", err)
	}
	if !o.Changed {
		t.Error("first Apply should report Changed=true")
	}
	conf := readFile(t, pacmanConf)
	for _, want := range []string{"[" + name + "]", "SigLevel = Required DatabaseOptional", "Server = https://example.com/pm-test-arch/$repo/os/$arch"} {
		if !strings.Contains(conf, want) {
			t.Errorf("pacman.conf missing %q", want)
		}
	}
	// Independent tool-acceptance probe: pacman's own config parser must accept
	// the appended [section]. `pacman-conf --repo <name>` dumps the section and
	// exits non-zero on a malformed/absent one — pure config parse, no network.
	if !pacmanParsesRepo(name) {
		t.Errorf("`pacman-conf --repo %s` failed after Apply — pacman did not accept the appended section", name)
	}
	if o2, err := m.Apply(ctx, repo); err != nil || o2.Changed {
		t.Errorf("idempotent re-Apply: changed=%v err=%v", o2.Changed, err)
	}
	if o3, err := m.Remove(ctx, name); err != nil || !o3.Changed {
		t.Errorf("Remove: changed=%v err=%v", o3.Changed, err)
	}
	if strings.Contains(readFile(t, pacmanConf), "["+name+"]") {
		t.Error("Remove left the [section] in pacman.conf")
	}
	if o4, err := m.Remove(ctx, name); err != nil || o4.Changed {
		t.Errorf("idempotent Remove: changed=%v err=%v", o4.Changed, err)
	}
}

// TestZypper_ApplyRemove_Container drives real `zypper addrepo`/`removerepo`:
// addrepo registers the alias (no fetch at add time with Autorefresh off), and
// `zypper lr <name>` must then list it. The trailing refresh against the
// unreachable URL is non-fatal by design.
func TestZypper_ApplyRemove_Container(t *testing.T) {
	m := realRepoMgr(t, pkg.Zypper)
	ctx := repoCtx(t)
	const name = "pm-test-zypper"
	t.Cleanup(func() { _, _ = m.Remove(context.Background(), name) })

	// Happy path keeps signature checking ON (the secure default); the
	// --no-gpgcheck operator override lives in repo_security_container_test.go.
	repo := Repository{Name: name, Zypper: &ZypperConfig{
		URL: "https://example.com/pm-test-suite", Description: "PM Test", Enabled: false, Autorefresh: false, GPGCheck: true,
	}}

	o, err := m.Apply(ctx, repo)
	if err != nil {
		t.Fatalf("Apply(zypper): %v", err)
	}
	if !o.Changed {
		t.Error("Apply should report Changed=true (zypper addrepo has no cheap idempotency probe)")
	}
	if !zypperRepoListed(t, name) {
		t.Errorf("`zypper lr %s` does not list the repo after Apply", name)
	}

	o3, err := m.Remove(ctx, name)
	if err != nil {
		t.Fatalf("Remove(zypper): %v", err)
	}
	if !o3.Changed {
		t.Error("Remove of a present repo should report Changed=true")
	}
	if zypperRepoListed(t, name) {
		t.Errorf("`zypper lr %s` still lists the repo after Remove", name)
	}
	o4, err := m.Remove(ctx, name)
	if err != nil {
		t.Fatalf("re-Remove(zypper): %v", err)
	}
	if o4.Changed {
		t.Error("Remove of an absent repo should report Changed=false (not found)")
	}
}

// zypperRepoListed reports whether `zypper lr <name>` exits 0 (the alias is
// registered). Run directly (root container) rather than through the Manager —
// the Manager has no read-back, so this is the independent verification.
func zypperRepoListed(t *testing.T, name string) bool {
	t.Helper()
	return osexec.Command("zypper", "--non-interactive", "lr", name).Run() == nil
}

// aptParsesRepo reports whether `apt-get --print-uris update` parses the written
// .sources and would fetch from uri. --print-uris prints the URIs apt WOULD
// fetch without fetching, so this proves apt accepted the deb822 file with no
// dependency on the unreachable example.com metadata.
func aptParsesRepo(t *testing.T, uri string) bool {
	t.Helper()
	out, _ := osexec.Command("apt-get", "--print-uris", "update").CombinedOutput()
	return strings.Contains(string(out), uri)
}

// dnfListsRepo reports whether `dnf repolist --all -C` lists the named repo.
// `-C` (cacheonly) reads configuration without a network refresh, so a repo id
// appearing proves dnf parsed and accepted the .repo file.
func dnfListsRepo(name string) bool {
	out, _ := osexec.Command("dnf", "repolist", "--all", "-C").CombinedOutput()
	return strings.Contains(string(out), name)
}

// pacmanParsesRepo reports whether `pacman-conf --repo <name>` exits 0. pacman's
// own config parser dumps the named [section] and fails on a malformed or absent
// one — a pure config parse with no network.
func pacmanParsesRepo(name string) bool {
	return osexec.Command("pacman-conf", "--repo", name).Run() == nil
}
