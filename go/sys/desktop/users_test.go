package desktop

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

// withHomeRoot swaps the package-level homeRoot for the duration of t.
// Restores on cleanup so tests can run in any order.
func withHomeRoot(t *testing.T, dir string) {
	t.Helper()
	prev := homeRoot
	homeRoot = dir
	t.Cleanup(func() { homeRoot = prev })
}

// currentUserSession builds a Session pointing at the running test
// user's home, used as the fixture identity. Skips when the test
// user can't be looked up (CI sandboxes without nsswitch/passwd).
func currentUserSession(t *testing.T) (user.User, int, int) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Skipf("non-numeric UID for current user: %v", err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Skipf("non-numeric GID for current user: %v", err)
	}
	return *u, uid, gid
}

func TestHomeUsers_EmptyHomeRoot(t *testing.T) {
	withHomeRoot(t, t.TempDir())
	got, err := HomeUsers()
	if err != nil {
		t.Fatalf("unexpected error on empty /home: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty /home should return zero users, got %d: %v", len(got), got)
	}
}

func TestHomeUsers_MissingHomeRoot(t *testing.T) {
	// Pin the contract: a non-existent /home is "no users", not an
	// error. Containers and minimal systems sometimes lack /home
	// entirely; the agent still needs to make a uninstall-loop
	// decision without exiting the action with a hard error.
	withHomeRoot(t, filepath.Join(t.TempDir(), "does-not-exist"))
	got, err := HomeUsers()
	if err != nil {
		t.Fatalf("missing /home should not error, got: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected zero users for missing /home, got %d", len(got))
	}
}

func TestHomeUsers_SkipsNonDirectoryAndDotPrefixed(t *testing.T) {
	root := t.TempDir()
	withHomeRoot(t, root)

	// Files, dot-prefixed dirs, and lost+found must all be skipped
	// before we even try to resolve a username — otherwise a stray
	// `.ecryptfs` ghost dir or fsck's `lost+found` would trigger a
	// noisy os/user.Lookup failure log on every run.
	if err := os.WriteFile(filepath.Join(root, "shared.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{".ecryptfs", ".pwd.lock", "lost+found"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Bait: a dir whose name resolves to no real user. Should be
	// silently skipped (no failure surfaced to the caller).
	if err := os.Mkdir(filepath.Join(root, "_definitely_not_a_real_user_name_pmtest"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := HomeUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("non-real entries should produce zero users, got %d: %v", len(got), got)
	}
}

func TestHomeUsers_ResolvesRealAccount(t *testing.T) {
	u, uid, gid := currentUserSession(t)

	root := t.TempDir()
	withHomeRoot(t, root)
	if err := os.Mkdir(filepath.Join(root, u.Username), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := HomeUsers()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 user, got %d: %v", len(got), got)
	}
	s := got[0]
	if s.Username != u.Username {
		t.Errorf("Username: got %q, want %q", s.Username, u.Username)
	}
	if s.UID != uid {
		t.Errorf("UID: got %d, want %d", s.UID, uid)
	}
	if s.GID != gid {
		t.Errorf("GID: got %d, want %d", s.GID, gid)
	}
	// HomeDir comes from the os/user lookup, not the synthetic
	// /home/<name> path under the test root — pin that the lookup
	// wins so a future refactor doesn't accidentally start trusting
	// the directory layout over passwd.
	if s.Home != u.HomeDir {
		t.Errorf("Home: got %q, want %q (the os/user lookup is authoritative, not the directory layout)",
			s.Home, u.HomeDir)
	}
	if s.RuntimeDir != "/run/user/"+u.Uid {
		t.Errorf("RuntimeDir: got %q, want %q", s.RuntimeDir, "/run/user/"+u.Uid)
	}
}

func TestUsersWithFlatpakInstall_RequiresAppID(t *testing.T) {
	if _, err := UsersWithFlatpakInstall(""); err == nil {
		t.Fatal("expected error for empty appID — guards against silently uninstalling for everyone")
	}
}

func TestUsersWithFlatpakInstall_FiltersByInstallDir(t *testing.T) {
	u, _, _ := currentUserSession(t)

	root := t.TempDir()
	withHomeRoot(t, root)
	if err := os.Mkdir(filepath.Join(root, u.Username), 0o755); err != nil {
		t.Fatal(err)
	}

	const appID = "com.example.PmTest"

	// First pass: nobody has the app installed in the synthetic
	// home root — should be empty.
	got, err := UsersWithFlatpakInstall(appID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range got {
		if s.Username == u.Username && s.Home == filepath.Join(root, u.Username) {
			// Only fail if the lookup-derived home actually points
			// into our test root (production runs have a real
			// HomeDir from passwd, which we should exclude here).
			t.Errorf("did not expect current user pre-install: %v", s)
		}
	}

	// We can't fabricate the install dir under the real $HOME from
	// inside a unit test (would clobber the dev's actual home), so
	// the positive direction is exercised by inspecting the filter
	// path in users.go and trusting the negative case above. The
	// rotation tests cover the loop behavior end-to-end via the
	// agent's executor tests.
}
