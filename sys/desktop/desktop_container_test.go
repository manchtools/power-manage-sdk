//go:build container

// Container-based real-execution tests for the desktop Manager. The hermetic
// FakeRunner/seam tests cover every branch with injected passwd lookups and
// loginctl output; these create REAL accounts and home directories inside the
// container and exercise the actual privilege drop (runuser), passwd/NSS
// enumeration, and per-user filesystem probes — so a real `runuser` env/identity
// change or an os/user lookup behaviour change is caught here.
//
// Runs in the container-tests lane (root): HomeUsers/UsersWithFlatpakInstall need
// to create accounts and RunAsRunner drops privilege to a *different* user, both
// of which require root. The Direct runner is correct (the lane is already root).
//
// ActiveSessions' populated GRAPHICAL path needs a real logind session of type
// x11/wayland, which cannot exist in headless CI (no display); that branch is
// unit-tested and exercised against real loginctl — empty — in the systemd
// integration test. Here ActiveSessions covers the loginctl-absent path.
package desktop

import (
	"context"
	"os"
	osexec "os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

func requireUseradd(t *testing.T) {
	t.Helper()
	if _, err := osexec.LookPath("useradd"); err != nil {
		t.Skip("useradd not on PATH; account-based desktop tests not exercisable")
	}
}

// mkUser creates a real account whose home is homeDir (created + skel-populated),
// registering a best-effort userdel cleanup. Returns the resolved *user.User.
func mkUser(t *testing.T, name, homeDir string) *user.User {
	t.Helper()
	_ = osexec.Command("userdel", "-r", name).Run() // clean slate
	if out, err := osexec.Command("useradd", "-m", "-d", homeDir, "-s", "/bin/bash", name).CombinedOutput(); err != nil {
		t.Fatalf("useradd %s: %v\n%s", name, err, out)
	}
	t.Cleanup(func() { _ = osexec.Command("userdel", "-r", name).Run() })
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatalf("lookup %s after useradd: %v", name, err)
	}
	return u
}

func realDesktop(t *testing.T, opts ...Option) Manager {
	t.Helper()
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := New(r, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func deskCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestHomeUsers_Container enumerates real accounts whose homes live under a
// custom home root, against real passwd/NSS: two real users are returned, while a
// stale dir with no account, a dot-dir, and lost+found are all skipped.
func TestHomeUsers_Container(t *testing.T) {
	requireUseradd(t)
	root := t.TempDir()
	alice := mkUser(t, "pmhomealice", filepath.Join(root, "pmhomealice"))
	_ = mkUser(t, "pmhomebob", filepath.Join(root, "pmhomebob"))

	// Decoys that must NOT be enumerated.
	if err := os.Mkdir(filepath.Join(root, "ghost"), 0o755); err != nil { // dir with no account
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".hidden"), 0o755); err != nil { // dot-dir
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "lost+found"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := realDesktop(t, WithHomeRoot(root)).HomeUsers(deskCtx(t))
	if err != nil {
		t.Fatalf("HomeUsers: %v", err)
	}
	names := make([]string, 0, len(got))
	for _, s := range got {
		names = append(names, s.Username)
	}
	slices.Sort(names)
	if want := []string{"pmhomealice", "pmhomebob"}; !slices.Equal(names, want) {
		t.Errorf("HomeUsers = %v, want %v (ghost/.hidden/lost+found must be skipped)", names, want)
	}
	// The returned account must carry the canonical UID/Home from passwd.
	for _, s := range got {
		if s.Username == "pmhomealice" {
			if strconv.Itoa(s.UID) != alice.Uid || s.Home != alice.HomeDir {
				t.Errorf("alice session = uid %d home %q, want uid %s home %q", s.UID, s.Home, alice.Uid, alice.HomeDir)
			}
		}
	}
}

// TestRunAsRunner_Container is the security-critical real test: a Runner built
// with RunAsRunner must actually run AS the target user (privilege dropped via
// runuser) with the per-user HOME/USER and the curated PATH.
func TestRunAsRunner_Container(t *testing.T) {
	requireUseradd(t)
	home := filepath.Join(t.TempDir(), "pmrunas")
	u := mkUser(t, "pmrunas", home)
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	s := Session{Username: "pmrunas", UID: uid, GID: gid, Home: u.HomeDir, RuntimeDir: "/run/user/" + u.Uid}
	base, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	ru, err := RunAsRunner(base, s)
	if err != nil {
		t.Fatalf("RunAsRunner: %v", err)
	}
	ctx := deskCtx(t)

	// Identity: `id -un` must print the target user — proves the real privilege drop.
	res, err := ru.Run(ctx, pmexec.Command{Name: "id", Args: []string{"-un"}})
	if err != nil {
		t.Fatalf("run id -un as pmrunas: %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "pmrunas" {
		t.Errorf("id -un = %q, want pmrunas (privilege was not dropped)", got)
	}

	// Environment: HOME/USER are the user's; PATH is the curated UserPath (the
	// user's ~/.local/bin first), NOT root's inherited PATH.
	res2, err := ru.Run(ctx, pmexec.Command{Name: "sh", Args: []string{"-c", `printf '%s|%s|%s' "$HOME" "$USER" "$PATH"`}})
	if err != nil {
		t.Fatalf("run env probe as pmrunas: %v", err)
	}
	parts := strings.SplitN(strings.TrimRight(res2.Stdout, "\n"), "|", 3)
	if len(parts) != 3 || parts[0] != u.HomeDir || parts[1] != "pmrunas" {
		t.Errorf("env = %v, want HOME=%q USER=pmrunas", parts, u.HomeDir)
	}
	if !strings.HasPrefix(parts[2], u.HomeDir+"/.local/bin:") {
		t.Errorf("PATH = %q, want it to start with the user's ~/.local/bin", parts[2])
	}

	// Working dir: runuser (no -l) keeps the parent's cwd, so a `pwd` with Dir
	// unset would print the test's cwd. Setting Command.Dir must make the real
	// child run there — proving Dir survives the runuser wrap (the RunAsCommand
	// parity that RunAsRunner now provides).
	res3, err := ru.Run(ctx, pmexec.Command{Name: "pwd", Dir: u.HomeDir})
	if err != nil {
		t.Fatalf("run pwd as pmrunas with Dir: %v", err)
	}
	if got := strings.TrimSpace(res3.Stdout); got != u.HomeDir {
		t.Errorf("pwd = %q, want %q (Command.Dir was not honored)", got, u.HomeDir)
	}
}

// TestUsersWithFlatpakInstall_Container probes the real per-user Flatpak install
// directory: only the user with $HOME/.local/share/flatpak/app/<appID> is returned.
func TestUsersWithFlatpakInstall_Container(t *testing.T) {
	requireUseradd(t)
	const appID = "org.test.PMApp"
	root := t.TempDir()
	flat := mkUser(t, "pmflatuser", filepath.Join(root, "pmflatuser"))
	_ = mkUser(t, "pmplainuser", filepath.Join(root, "pmplainuser"))
	if err := os.MkdirAll(filepath.Join(flat.HomeDir, ".local/share/flatpak/app", appID), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := realDesktop(t, WithHomeRoot(root)).UsersWithFlatpakInstall(deskCtx(t), appID)
	if err != nil {
		t.Fatalf("UsersWithFlatpakInstall: %v", err)
	}
	if len(got) != 1 || got[0].Username != "pmflatuser" {
		names := make([]string, len(got))
		for i, s := range got {
			names[i] = s.Username
		}
		t.Errorf("UsersWithFlatpakInstall = %v, want [pmflatuser] only", names)
	}
}

// TestActiveSessions_NoLoginctl_Container: with loginctl absent (the container-
// tests base image ships no systemd), ActiveSessions returns an empty slice and
// NO error — the documented "no logind, no sessions" contract, against the real
// (absent) binary.
func TestActiveSessions_NoLoginctl_Container(t *testing.T) {
	if _, err := osexec.LookPath("loginctl"); err == nil {
		t.Skip("loginctl present here; the absent-path assertion does not apply")
	}
	got, err := realDesktop(t).ActiveSessions(deskCtx(t))
	if err != nil {
		t.Fatalf("ActiveSessions with loginctl absent must not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ActiveSessions = %v, want empty when loginctl is absent", got)
	}
}
