package desktop

import (
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

// The PATH behaviours these tests pinned (curated PATH set, and a caller PATH
// dropped/overridden) moved with the per-user exec path itself: see
// TestRunAsRunner_WrapsCommandAsUser and TestRunAsRunner_CallerPathDropped.
