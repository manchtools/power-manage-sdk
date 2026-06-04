package remote

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateDestination_RejectsEmptyOrRoot covers the cheapest layer of
// the path-safety contract: the values most likely to slip through a
// caller's input plumbing as defaults / zero values.
func TestValidateDestination_RejectsEmptyOrRoot(t *testing.T) {
	for _, p := range []string{"", "/", "  "} {
		t.Run("dest="+p, func(t *testing.T) {
			err := validateDestination(p)
			if !errors.Is(err, ErrUnsafeDestination) {
				t.Fatalf("validateDestination(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", p, err)
			}
		})
	}
}

// TestValidateDestination_RejectsRelative — relative paths are a vector for
// "fetch to my homedir" surprises depending on the agent's cwd. The
// underlying sys/fs.ResolveAndValidatePath requires absolute, so this is
// also a sanity check that we plumb that requirement through.
func TestValidateDestination_RejectsRelative(t *testing.T) {
	for _, p := range []string{"foo", "./foo", "../foo", "subdir/file"} {
		t.Run("dest="+p, func(t *testing.T) {
			err := validateDestination(p)
			if !errors.Is(err, ErrUnsafeDestination) {
				t.Fatalf("validateDestination(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", p, err)
			}
		})
	}
}

// TestValidateDestination_RejectsProtectedPaths — sys/fs.IsProtectedPath
// flags the canonical system dirs (exact match, not prefix). validateDestination
// must refuse to mutate any of them.
func TestValidateDestination_RejectsProtectedPaths(t *testing.T) {
	for _, p := range []string{"/etc", "/boot", "/proc", "/sys", "/usr", "/var", "/bin", "/sbin"} {
		t.Run("dest="+p, func(t *testing.T) {
			err := validateDestination(p)
			if !errors.Is(err, ErrUnsafeDestination) {
				t.Fatalf("validateDestination(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", p, err)
			}
		})
	}
}

// TestValidateDestination_AcceptsNormalAbsolutePaths — anything that isn't
// the empty string, root, a protected dir, or a relative path should pass.
// Uses t.TempDir() to get a real, writable absolute path that
// ResolveAndValidatePath will accept.
func TestValidateDestination_AcceptsNormalAbsolutePaths(t *testing.T) {
	tmp := t.TempDir()
	for _, p := range []string{
		tmp,
		filepath.Join(tmp, "newfile"),
		filepath.Join(tmp, "subdir", "file"),
		"/var/lib/power-manage/something", // doesn't need to exist; ResolveAndValidatePath walks up
		"/etc/power-manage/something",
	} {
		t.Run("dest="+p, func(t *testing.T) {
			if err := validateDestination(p); err != nil {
				t.Fatalf("validateDestination(%q) unexpected err: %v", p, err)
			}
		})
	}
}

// TestValidateDestination_RejectsSymlinkEscape — the user provides a path
// inside dest that resolves (via a symlink in an existing parent) to a
// protected location. ResolveAndValidatePath flattens the symlink; our
// IsProtectedPath check then catches it.
func TestValidateDestination_RejectsSymlinkEscape(t *testing.T) {
	tmp := t.TempDir()
	link := filepath.Join(tmp, "escape")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	// Use a path whose existing parent (tmp) contains the symlink; the
	// flattened form points at /etc, which is protected.
	dest := filepath.Join(link, "")
	if err := validateDestination(dest); !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("validateDestination(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", dest, err)
	}
}

// TestCanWipe_AllowsManagedRoots — the Wipe allow-list is the second layer
// of safety. Even after validateDestination passes, Wipe additionally
// refuses anything not under one of the project-managed roots OR
// previously seen by a successful Fetch (RecordDest).
func TestCanWipe_AllowsManagedRoots(t *testing.T) {
	for _, p := range []string{
		"/var/lib/power-manage/x",
		"/var/lib/power-manage/sub/dir",
		"/etc/power-manage/x",
	} {
		t.Run("dest="+p, func(t *testing.T) {
			if err := canWipe(p); err != nil {
				t.Fatalf("canWipe(%q) unexpected err: %v", p, err)
			}
		})
	}
}

// TestCanWipe_RefusesUnregisteredPath — paths outside the allow-list and
// not previously recorded must be refused, even if validateDestination
// would have accepted them for a Fetch.
func TestCanWipe_RefusesUnregisteredPath(t *testing.T) {
	tmp := t.TempDir() // /tmp/<random>, not in the allow-list
	dest := filepath.Join(tmp, "never-recorded")
	if err := canWipe(dest); !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("canWipe(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", dest, err)
	}
}

// TestCanWipe_RecordDestRoundTrip — paths a previous Fetch recorded with
// RecordDest become wipe-eligible. The store is process-local; tests
// that call RecordDest must clean up to keep the suite hermetic.
func TestCanWipe_RecordDestRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	dest := filepath.Join(tmp, "recorded-by-fetch")
	t.Cleanup(func() { forgetDest(dest) })

	if err := canWipe(dest); err == nil {
		t.Fatalf("canWipe(%q) before RecordDest returned nil; expected error", dest)
	}
	RecordDest(dest)
	if err := canWipe(dest); err != nil {
		t.Fatalf("canWipe(%q) after RecordDest err: %v", dest, err)
	}
	forgetDest(dest)
	if err := canWipe(dest); err == nil {
		t.Fatalf("canWipe(%q) after forgetDest returned nil; expected error", dest)
	}
}

// TestCanWipe_RefusesProtectedEvenIfRecorded — RecordDest must not be a
// jailbreak for the protected-path check. If someone manages to feed a
// protected path through Fetch (which validateDestination already rejects)
// and then call Wipe, canWipe must STILL refuse.
func TestCanWipe_RefusesProtectedEvenIfRecorded(t *testing.T) {
	for _, p := range []string{"/etc", "/var"} {
		t.Run("dest="+p, func(t *testing.T) {
			RecordDest(p)
			t.Cleanup(func() { forgetDest(p) })
			err := canWipe(p)
			if err == nil || !strings.Contains(err.Error(), "unsafe") {
				t.Fatalf("canWipe(%q) = %v; want unsafe rejection", p, err)
			}
		})
	}
}
