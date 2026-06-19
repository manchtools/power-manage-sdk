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
//
// The set covers BOTH exact protected roots (/etc, /var) AND protected
// *subpaths* (/etc/cron.d/x, ...). The subpath cases are the security point:
// the old exact-match IsProtectedPath let a recorded /etc/cron.d/x slip the
// guard, so a Fetch→RecordDest→Wipe round-trip could rm -rf a privilege
// vector. canWipe must refuse a protected subtree at ANY depth, recorded or
// not.
func TestCanWipe_RefusesProtectedEvenIfRecorded(t *testing.T) {
	cases := append([]string{"/etc", "/var"}, protectedSubpaths...)
	for _, p := range cases {
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

// protectedSubpaths are real-world privilege-escalation / data-destruction
// targets that live ONE OR MORE levels under a protected system root. The set
// is derived from the design intent encoded in sys/fs.protectedPrefixRoots
// (deny-by-default subtree), NOT from the artifact under test (IsProtectedPath,
// whose exact-match semantics are exactly the bug). Writing or wiping any of
// these via the remote ingester is a root code-exec / privesc vector, which
// sys/remote/doc.go promises is impossible.
var protectedSubpaths = []string{
	"/etc/cron.d/evil",                     // root cron job → code exec
	"/etc/sudoers.d/evil",                  // grant NOPASSWD → privesc
	"/etc/systemd/system/evil.service",     // unit drop-in → code exec
	"/usr/bin/sshd",                        // overwrite a system binary
	"/usr/lib/systemd/system/sshd.service", // hijack a service
	"/bin/ls",                              // overwrite a core binary
	"/sbin/init",                           // overwrite PID1
	"/lib/x86_64-linux-gnu/libc.so.6",      // overwrite libc
	"/boot/grub/grub.cfg",                  // bootloader tamper
	"/home/alice/.ssh/authorized_keys",     // add an SSH key → account takeover
	"/home/alice/.bashrc",                  // shell-init code exec
	"/root/.bashrc",                        // root shell-init code exec
	"/var/lib/postgresql/data",             // destroy persistent DB state
	"/proc/sysrq-trigger",                  // kernel control
	"/sys/kernel/uevent_helper",            // kernel-invoked binary
}

// TestValidateDestination_RejectsProtectedSubpaths pins the fail-open fix:
// Fetch must refuse to write attacker-controlled remote content to any path
// under a protected system subtree. Derived from intent (protectedPrefixRoots),
// these were ACCEPTED by the old exact-match IsProtectedPath.
func TestValidateDestination_RejectsProtectedSubpaths(t *testing.T) {
	for _, p := range protectedSubpaths {
		t.Run("dest="+p, func(t *testing.T) {
			if err := validateDestination(p); !errors.Is(err, ErrUnsafeDestination) {
				t.Fatalf("validateDestination(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", p, err)
			}
		})
	}
}

// TestCanWipe_RejectsProtectedSubpaths — the Wipe-side mirror: ABSENT/wipe of
// a protected subtree must be refused even before the recorded-set check.
func TestCanWipe_RejectsProtectedSubpaths(t *testing.T) {
	for _, p := range protectedSubpaths {
		t.Run("dest="+p, func(t *testing.T) {
			if err := canWipe(p); !errors.Is(err, ErrUnsafeDestination) {
				t.Fatalf("canWipe(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", p, err)
			}
		})
	}
}

// TestValidateDestination_StillAcceptsManagedRootsUnderProtectedPrefix is the
// regression guard for the carve-out: the agent's own managed roots live UNDER
// protected prefixes (/etc/power-manage is under /etc, /var/lib/power-manage is
// under /var/lib), so the deny-by-default subtree check must explicitly exempt
// them or the agent can no longer manage its own state. Pins the boundary so a
// future tightening of the deny set can't silently break legitimate writes.
func TestValidateDestination_StillAcceptsManagedRootsUnderProtectedPrefix(t *testing.T) {
	for _, p := range []string{
		"/etc/power-manage",
		"/etc/power-manage/sub/file",
		"/var/lib/power-manage",
		"/var/lib/power-manage/sub/dir/file",
	} {
		t.Run("dest="+p, func(t *testing.T) {
			if err := validateDestination(p); err != nil {
				t.Fatalf("validateDestination(%q) unexpected err: %v", p, err)
			}
		})
	}
}

// TestIsManagedRoot_BoundaryRobustToMissingTrailingSlash pins that the
// sibling-prefix boundary does NOT depend on wipeAllowedRoots entries being
// written with a trailing slash: even a no-slash entry must refuse a hostile
// sibling (/etc/power-manage-evil) while still matching real managed subpaths.
func TestIsManagedRoot_BoundaryRobustToMissingTrailingSlash(t *testing.T) {
	orig := wipeAllowedRoots
	t.Cleanup(func() { wipeAllowedRoots = orig })
	wipeAllowedRoots = []string{"/etc/power-manage"} // intentionally no trailing slash

	if isManagedRoot("/etc/power-manage-evil") {
		t.Error("isManagedRoot matched a hostile sibling /etc/power-manage-evil; boundary must not depend on a trailing slash")
	}
	if !isManagedRoot("/etc/power-manage") {
		t.Error("isManagedRoot must match the exact managed root")
	}
	if !isManagedRoot("/etc/power-manage/x") {
		t.Error("isManagedRoot must match a real managed subpath")
	}
}

// TestCanWipe_RejectsManagedRootSiblingPrefix — the carve-out must use a
// trailing-slash boundary so a hostile sibling like /etc/power-manage-evil is
// NOT mistaken for the managed root /etc/power-manage and is refused as a
// protected /etc subtree.
func TestCanWipe_RejectsManagedRootSiblingPrefix(t *testing.T) {
	for _, p := range []string{"/etc/power-manage-evil/x", "/var/lib/power-manage-evil"} {
		t.Run("dest="+p, func(t *testing.T) {
			if err := canWipe(p); !errors.Is(err, ErrUnsafeDestination) {
				t.Fatalf("canWipe(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", p, err)
			}
		})
	}
}
