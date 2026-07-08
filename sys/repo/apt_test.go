package repo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// stdinOf reads back the stdin a recorded command carried (the FakeRunner never
// consumes it, so it is still readable).
func stdinOf(t *testing.T, c pmexec.Command) string {
	t.Helper()
	if c.Stdin == nil {
		return ""
	}
	b, err := io.ReadAll(c.Stdin)
	if err != nil {
		t.Fatalf("read recorded stdin: %v", err)
	}
	return string(b)
}

func TestApt_Apply_DearmorsKeyWritesSourcesAndUpdates(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Apt)
	fr.Push(pmexec.Result{Stdout: "BINKEY"}, nil) // gpg --dearmor → binary keyring on stdout
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{
		URL:          "https://h/a",
		Distribution: "bookworm",
		Components:   []string{"main", "contrib"},
		Arch:         "amd64",
		GPGKey:       []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\narmored\n-----END-----\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed {
		t.Error("first Apply reports Changed=true")
	}

	// The armored key is dearmored via unprivileged gpg with the key on stdin
	// (never on argv), and the binary result lands in the keyring.
	calls := fr.Calls()
	if argvs(fr)[0] != "gpg --dearmor" || calls[0].Escalate {
		t.Errorf("first cmd = %q (escalate=%v), want an unprivileged `gpg --dearmor`", argvs(fr)[0], calls[0].Escalate)
	}
	if got := stdinOf(t, calls[0]); !strings.Contains(got, "BEGIN PGP PUBLIC KEY") {
		t.Errorf("gpg stdin = %q, want the armored key", got)
	}
	if got := ff.wrote("/etc/apt/keyrings/corp.gpg"); got != "BINKEY" {
		t.Errorf("keyring = %q, want the dearmored bytes", got)
	}

	wantSources := "# Repository: corp\n" +
		"Types: deb\n" +
		"URIs: https://h/a\n" +
		"Suites: bookworm\n" +
		"Components: main contrib\n" +
		"Architectures: amd64\n" +
		"Signed-By: /etc/apt/keyrings/corp.gpg\n"
	if got := ff.wrote("/etc/apt/sources.list.d/corp.sources"); got != wantSources {
		t.Errorf("sources =\n%q\nwant\n%q", got, wantSources)
	}
	if !ff.didCall("Mkdir:/etc/apt/keyrings") {
		t.Error("the keyrings directory must be ensured before the keyring is written")
	}
	if argvs(fr)[len(argvs(fr))-1] != "apt-get update" {
		t.Errorf("last cmd = %q, want `apt-get update`", argvs(fr)[len(argvs(fr))-1])
	}
}

func TestApt_Apply_TrustedNoKey(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Apt)
	if _, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{
		URL: "https://h/a", Trusted: true,
	}}); err != nil {
		t.Fatal(err)
	}
	got := ff.wrote("/etc/apt/sources.list.d/r.sources")
	if !strings.Contains(got, "Trusted: yes") {
		t.Errorf("sources missing Trusted: yes:\n%q", got)
	}
	if strings.Contains(got, "Signed-By") {
		t.Errorf("no key configured, but Signed-By written:\n%q", got)
	}
	// No key → no gpg dearmor and no keyring write; only apt-get update runs.
	if got := argvs(fr); len(got) != 1 || got[0] != "apt-get update" {
		t.Errorf("commands = %v, want only apt-get update (no gpg)", got)
	}
	if ff.didCall("WriteFile:/etc/apt/keyrings/r.gpg") {
		t.Error("no key configured, but a keyring was written")
	}
}

func TestApt_Apply_Idempotent(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Apt)
	fr.Push(pmexec.Result{Stdout: "BINKEY"}, nil) // gpg --dearmor
	keyFile := "/etc/apt/keyrings/corp.gpg"
	repoFile := "/etc/apt/sources.list.d/corp.sources"
	ff.read[keyFile] = []byte("BINKEY") // keyring already matches the dearmored key
	ff.read[repoFile] = []byte("# Repository: corp\nTypes: deb\nURIs: https://h/a\nSuites: /\nSigned-By: /etc/apt/keyrings/corp.gpg\n")
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{
		URL: "https://h/a", GPGKey: []byte("armored"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Changed {
		t.Errorf("matching key + sources must report Changed=false; sources rewritten? %v", ff.didCall("WriteFile:"+repoFile))
	}
	if ff.didCall("WriteFile:" + keyFile) {
		t.Error("matching keyring must not be rewritten")
	}
	if ff.didCall("WriteFile:" + repoFile) {
		t.Error("matching sources must not be rewritten")
	}
	// gpg ran (to compute the comparison) but apt-get update must NOT (nothing changed).
	for _, c := range argvs(fr) {
		if c == "apt-get update" {
			t.Error("idempotent Apply must not refresh the index")
		}
	}
}

func TestApt_Apply_KeyDiffersTriggersRewrite(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Apt)
	fr.Push(pmexec.Result{Stdout: "NEWKEY"}, nil)
	keyFile := "/etc/apt/keyrings/corp.gpg"
	ff.read[keyFile] = []byte("OLDKEY") // installed key differs from dearmored
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{
		URL: "https://h/a", GPGKey: []byte("armored"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed {
		t.Error("a differing key must report Changed=true")
	}
	if got := ff.wrote(keyFile); got != "NEWKEY" {
		t.Errorf("keyring = %q, want the updated NEWKEY", got)
	}
	if !strings.Contains(out.Result.Stdout, "GPG key differs, updating") {
		t.Errorf("expected a 'key differs' note, got %q", out.Result.Stdout)
	}
}

func TestApt_Apply_DearmorFailureIsFatal(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Apt)
	fr.Push(pmexec.Result{ExitCode: 2, Stderr: "gpg: no valid OpenPGP data"}, nil)
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{
		URL: "https://h/a", GPGKey: []byte("not a key"),
	}})
	if err == nil || !strings.Contains(err.Error(), "dearmor GPG key") {
		t.Fatalf("err = %v, want a wrapped dearmor failure", err)
	}
	if out.Changed {
		t.Error("a dearmor failure must report Changed=false")
	}
}

func TestApt_Apply_ConflictCleanup(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Apt)
	dir := "/etc/apt/sources.list.d"
	ff.entries[dir] = []fs.DirEntry{
		{Name: "other.sources", IsDir: false},
		{Name: "corp.sources", IsDir: false}, // the target's own file — must be skipped
		{Name: "sub", IsDir: true},           // a directory — must be skipped
		{Name: "readme.txt", IsDir: false},   // not a repo file — must be skipped
	}
	// A different repo file that references the SAME url under a different key.
	ff.read[dir+"/other.sources"] = []byte("Types: deb\nURIs: https://h/a\nSigned-By: /etc/apt/keyrings/other.gpg\n")
	ff.read[dir+"/corp.sources"] = []byte("URIs: https://h/a\n") // would match, but it's the target → skipped

	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{URL: "https://h/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed {
		t.Error("removing a conflicting repo must report Changed=true")
	}
	if !ff.didCall("Remove:" + dir + "/other.sources") {
		t.Error("the conflicting repo file was not removed")
	}
	if !ff.didCall("Remove:/etc/apt/keyrings/other.gpg") {
		t.Error("the conflicting repo's Signed-By keyring was not removed")
	}
	// The target's own files must never be removed by the cleanup.
	if ff.didCall("Remove:" + dir + "/corp.sources") {
		t.Error("cleanup must skip the target repo's own .sources file")
	}
}

func TestApt_Apply_ConflictCleanup_ListFormatKey(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Apt)
	dir := "/etc/apt/sources.list.d"
	ff.entries[dir] = []fs.DirEntry{{Name: "legacy.list", IsDir: false}}
	ff.read[dir+"/legacy.list"] = []byte("deb [signed-by=/etc/apt/keyrings/legacy.gpg] https://h/a stable main\n")
	if _, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{URL: "https://h/a"}}); err != nil {
		t.Fatal(err)
	}
	if !ff.didCall("Remove:/etc/apt/keyrings/legacy.gpg") {
		t.Error("the one-line signed-by= keyring was not extracted and removed")
	}
	if !ff.didCall("Remove:" + dir + "/legacy.list") {
		t.Error("the conflicting .list file was not removed")
	}
}

func TestApt_Apply_ConflictScanErrorIsNonFatal(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Apt)
	ff.errs["ReadDir:/etc/apt/sources.list.d"] = errors.New("io")
	fr.Push(pmexec.Result{Stdout: "BINKEY"}, nil)
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{URL: "https://h/a", GPGKey: []byte("k")}})
	if err != nil {
		t.Fatalf("a conflict-scan error must not fail Apply, got %v", err)
	}
	if !strings.Contains(out.Result.Stdout, "could not scan") {
		t.Errorf("expected a scan warning, got %q", out.Result.Stdout)
	}
}

func TestApt_Apply_LegacyCleanup(t *testing.T) {
	m, ff, _ := newTestManager(t, pkg.Apt)
	ff.present["/etc/apt/sources.list.d/corp.list"] = true
	ff.present["/etc/apt/trusted.gpg.d/corp.gpg"] = true
	out, err := m.Apply(context.Background(), Repository{Name: "corp", Apt: &AptConfig{URL: "https://h/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed {
		t.Error("legacy cleanup must report Changed=true")
	}
	if !ff.didCall("Remove:/etc/apt/sources.list.d/corp.list") {
		t.Error("legacy .list not removed")
	}
	if !ff.didCall("Remove:/etc/apt/trusted.gpg.d/corp.gpg") {
		t.Error("legacy trusted.gpg.d key not removed")
	}
}

func TestApt_Apply_MkdirAndWriteErrorsAreFatal(t *testing.T) {
	t.Run("mkdir error", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Apt)
		ff.errs["Mkdir:/etc/apt/keyrings"] = errors.New("ro")
		if _, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a"}}); err == nil ||
			!strings.Contains(err.Error(), "create keyrings directory") {
			t.Fatalf("err = %v, want a wrapped mkdir failure", err)
		}
	})
	t.Run("sources write error", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Apt)
		ff.errs["WriteFile:/etc/apt/sources.list.d/r.sources"] = errors.New("ro")
		if _, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a"}}); err == nil ||
			!strings.Contains(err.Error(), "write repo file") {
			t.Fatalf("err = %v, want a wrapped sources write failure", err)
		}
	})
	t.Run("keyring write error", func(t *testing.T) {
		m, ff, fr := newTestManager(t, pkg.Apt)
		fr.Push(pmexec.Result{Stdout: "BINKEY"}, nil)
		ff.errs["WriteFile:/etc/apt/keyrings/r.gpg"] = errors.New("ro")
		_, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a", GPGKey: []byte("k")}})
		if err == nil || !strings.Contains(err.Error(), "install GPG key") {
			t.Fatalf("err = %v, want a wrapped keyring write failure", err)
		}
	})
}

func TestApt_Apply_UpdateFailureIsNonFatal(t *testing.T) {
	m, _, fr := newTestManager(t, pkg.Apt)
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "could not resolve host"}, nil) // apt-get update fails
	out, err := m.Apply(context.Background(), Repository{Name: "r", Apt: &AptConfig{URL: "https://h/a"}})
	if err != nil {
		t.Fatalf("apt-get update failure must be non-fatal, got %v", err)
	}
	if !strings.Contains(out.Result.Stdout, "apt-get update failed") {
		t.Errorf("expected an update warning, got %q", out.Result.Stdout)
	}
}

func TestApt_Remove(t *testing.T) {
	repoFile := "/etc/apt/sources.list.d/corp.sources"
	legacyFile := "/etc/apt/sources.list.d/corp.list"
	keyFile := "/etc/apt/keyrings/corp.gpg"

	t.Run("present removes all three", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Apt)
		ff.present[repoFile] = true
		out, err := m.Remove(context.Background(), "corp")
		if err != nil {
			t.Fatal(err)
		}
		if !out.Changed {
			t.Error("removing a present repo reports Changed=true")
		}
		for _, p := range []string{repoFile, legacyFile, keyFile} {
			if !ff.didCall("Remove:" + p) {
				t.Errorf("Remove(%s) was not called", p)
			}
		}
	})
	t.Run("absent is idempotent", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Apt)
		out, err := m.Remove(context.Background(), "corp")
		if err != nil {
			t.Fatal(err)
		}
		if out.Changed {
			t.Error("nothing present → Changed=false")
		}
		if ff.didCall("Remove:" + repoFile) {
			t.Error("nothing present → no deletes")
		}
	})
	t.Run("exists probe error fails closed", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Apt)
		ff.errs["Exists:"+repoFile] = errors.New("probe")
		if _, err := m.Remove(context.Background(), "corp"); err == nil {
			t.Fatal("a probe error must fail closed")
		}
	})
	t.Run("primary remove error is fatal", func(t *testing.T) {
		m, ff, _ := newTestManager(t, pkg.Apt)
		ff.present[keyFile] = true // something exists → proceeds to delete
		ff.errs["Remove:"+repoFile] = errors.New("denied")
		if _, err := m.Remove(context.Background(), "corp"); err == nil ||
			!strings.Contains(err.Error(), "remove repo file") {
			t.Fatalf("err = %v, want a wrapped primary-remove failure", err)
		}
	})
}

// #302: apt rejecting the JUST-WRITTEN sources file (e.g. the malformed
// "absolute Suite Component" form) must roll the file back and FAIL —
// leaving it in place while reporting success breaks every apt
// operation on the host.
func TestApt_Apply_MalformedSourcesRollsBackAndFails(t *testing.T) {
	const repoFile = "/etc/apt/sources.list.d/docker.sources"

	t.Run("prior content is restored", func(t *testing.T) {
		m, ff, fr := newTestManager(t, pkg.Apt)
		ff.read[repoFile] = []byte("# old good content\n")
		fr.Push(pmexec.Result{}, fmt.Errorf("apt-get: exit 100: E: Malformed entry 1 in sources file %s (absolute Suite Component)", repoFile))

		out, err := m.Apply(context.Background(), Repository{Name: "docker", Apt: &AptConfig{
			URL:          "https://download.docker.com/linux/ubuntu",
			Distribution: "noble",
			Components:   []string{"stable"},
		}})
		if err == nil {
			t.Fatalf("Apply must fail when apt rejects the written file, got success: %+v", out)
		}
		if out.Changed {
			t.Error("a rolled-back apply must not report Changed")
		}
		if got := ff.wrote(repoFile); got != "# old good content\n" {
			t.Errorf("repo file = %q, want the pre-apply content restored", got)
		}
	})

	t.Run("fresh file is removed; diagnostic only on stderr", func(t *testing.T) {
		m, ff, fr := newTestManager(t, pkg.Apt)
		// The path arrives ONLY via Result.Stderr — pins that the guard
		// reads the raw streams, not just the folded error string (CR).
		fr.Push(pmexec.Result{
			ExitCode: 100,
			Stderr:   fmt.Sprintf("E: Malformed entry 1 in sources file %s (absolute Suite Component)", repoFile),
		}, errors.New("apt-get: exit 100"))

		_, err := m.Apply(context.Background(), Repository{Name: "docker", Apt: &AptConfig{
			URL:          "https://download.docker.com/linux/ubuntu",
			Distribution: "noble",
			Components:   []string{"stable"},
		}})
		if err == nil {
			t.Fatal("Apply must fail when apt rejects the written file")
		}
		if !ff.didCall("Remove:" + repoFile) {
			t.Error("a fresh malformed file must be removed, not left to break apt")
		}
	})
}

// #302 counterpart: an update failure that does NOT name our file (a
// network error, a broken THIRD-PARTY repo) stays a warning — the
// config landed and is valid; failing would block converging repos on
// hosts with unrelated apt breakage.
func TestApt_Apply_UnrelatedUpdateFailureStaysWarning(t *testing.T) {
	m, ff, fr := newTestManager(t, pkg.Apt)
	fr.Push(pmexec.Result{}, fmt.Errorf("apt-get: exit 100: Could not resolve 'download.docker.com'"))

	out, err := m.Apply(context.Background(), Repository{Name: "docker", Apt: &AptConfig{
		URL:          "https://download.docker.com/linux/ubuntu",
		Distribution: "noble",
		Components:   []string{"stable"},
	}})
	if err != nil {
		t.Fatalf("a network-shaped update failure must stay non-fatal: %v", err)
	}
	if !out.Changed {
		t.Error("the configuration landed; Changed must be true")
	}
	if got := ff.wrote("/etc/apt/sources.list.d/docker.sources"); !strings.Contains(got, "Suites: noble") {
		t.Errorf("valid sources file must be kept, got %q", got)
	}
}
