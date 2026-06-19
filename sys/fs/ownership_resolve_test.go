//go:build unix

package fs

import (
	"os/user"
	"strconv"
	"testing"
)

// ResolveOwnership maps owner/group NAMES to numeric ids for the fd-based
// fchown helpers. An empty name resolves to -1 ("leave unchanged", the
// chown(2) sentinel); an unknown name is an error (fail closed — never
// fall back to root/0 or to "leave unchanged" silently, which would let a
// typo widen ownership).
func TestResolveOwnership(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	wantUID, _ := strconv.Atoi(u.Uid)
	wantGID, _ := strconv.Atoi(u.Gid)
	g, gErr := user.LookupGroupId(u.Gid)

	t.Run("both empty leaves unchanged", func(t *testing.T) {
		uid, gid, err := ResolveOwnership("", "")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if uid != -1 || gid != -1 {
			t.Errorf("got (%d,%d), want (-1,-1)", uid, gid)
		}
	})

	t.Run("known owner only", func(t *testing.T) {
		uid, gid, err := ResolveOwnership(u.Username, "")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if uid != wantUID || gid != -1 {
			t.Errorf("got (%d,%d), want (%d,-1)", uid, gid, wantUID)
		}
	})

	t.Run("known owner and group", func(t *testing.T) {
		if gErr != nil {
			t.Skipf("cannot resolve current group: %v", gErr)
		}
		uid, gid, err := ResolveOwnership(u.Username, g.Name)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if uid != wantUID || gid != wantGID {
			t.Errorf("got (%d,%d), want (%d,%d)", uid, gid, wantUID, wantGID)
		}
	})

	t.Run("unknown owner is an error", func(t *testing.T) {
		if _, _, err := ResolveOwnership("pm-ws6-no-such-user-zzz", ""); err == nil {
			t.Errorf("ResolveOwnership(unknown user): want error, got nil")
		}
	})

	t.Run("unknown group is an error", func(t *testing.T) {
		if _, _, err := ResolveOwnership("", "pm-ws6-no-such-group-zzz"); err == nil {
			t.Errorf("ResolveOwnership(unknown group): want error, got nil")
		}
	})
}
