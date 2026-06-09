package desktop

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// UserPath is the curated PATH a per-user command should run with. It
// must NOT depend on the agent's (root's) PATH, and must put the user's
// own bin dirs first so a user's ~/.local/bin wins over a system binary
// of the same name.
func TestUserPath(t *testing.T) {
	s := Session{Username: "alice", Home: "/home/alice"}
	got := UserPath(s)
	dirs := strings.Split(got, ":")

	if !slices.Contains(dirs, "/home/alice/.local/bin") {
		t.Errorf("UserPath must include ~/.local/bin, got %q", got)
	}
	if !slices.Contains(dirs, "/usr/bin") {
		t.Errorf("UserPath must include /usr/bin, got %q", got)
	}
	// User bin dirs come first so they shadow system binaries.
	localIdx := slices.Index(dirs, "/home/alice/.local/bin")
	usrIdx := slices.Index(dirs, "/usr/bin")
	if localIdx == -1 || usrIdx == -1 || localIdx > usrIdx {
		t.Errorf("~/.local/bin must precede /usr/bin, got %q", got)
	}

	// sbin dirs are intentionally INCLUDED (usr-merged distros put them
	// on every user's default PATH) but ordered AFTER the bin dirs: a
	// user binary of the same name must win and sbin resolution is a last
	// resort. Pin both the inclusion and the ordering so a reorder or
	// accidental drop is caught.
	binIdx := slices.Index(dirs, "/bin")
	for _, sbin := range []string{"/usr/local/sbin", "/usr/sbin", "/sbin"} {
		sbinIdx := slices.Index(dirs, sbin)
		if sbinIdx == -1 {
			t.Errorf("UserPath must include %s (usr-merged default), got %q", sbin, got)
			continue
		}
		if sbinIdx < usrIdx {
			t.Errorf("%s must come after /usr/bin so bin dirs win, got %q", sbin, got)
		}
		if binIdx != -1 && sbinIdx < binIdx {
			t.Errorf("%s must come after /bin, got %q", sbin, got)
		}
	}
}

// RunAsCommand must set the curated user PATH on the child env — the
// previous shape left PATH unset entirely (EnvFor omits it), so per-user
// commands ran with no PATH / runuser's compiled-in default rather than
// the user's, and ~/.local/bin was never on PATH.
func TestRunAsCommand_SetsCuratedUserPath(t *testing.T) {
	s := Session{Username: "alice", UID: 1000, Home: "/home/alice", RuntimeDir: "/run/user/1000"}
	cmd, err := RunAsCommand(context.Background(), s, nil, "true")
	if err != nil {
		t.Fatalf("RunAsCommand: %v", err)
	}
	want := "PATH=" + UserPath(s)
	if !slices.Contains(cmd.Env, want) {
		t.Errorf("RunAsCommand env must contain the curated %q; env=%v", want, cmd.Env)
	}
}

// An action-supplied PATH in extraEnv must not override the curated
// user PATH — the curated value is applied last so it wins, matching the
// streaming path which refuses a caller-supplied PATH outright.
func TestRunAsCommand_CuratedPathWinsOverExtraEnv(t *testing.T) {
	s := Session{Username: "alice", UID: 1000, Home: "/home/alice", RuntimeDir: "/run/user/1000"}
	cmd, err := RunAsCommand(context.Background(), s, []string{"PATH=/attacker/bin"}, "true")
	if err != nil {
		t.Fatalf("RunAsCommand: %v", err)
	}
	// Last PATH entry wins under exec semantics; it must be the curated one.
	var lastPath string
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "PATH=") {
			lastPath = e
		}
	}
	if lastPath != "PATH="+UserPath(s) {
		t.Errorf("curated PATH must win over extraEnv PATH; effective=%q", lastPath)
	}
}
