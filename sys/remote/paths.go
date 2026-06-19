package remote

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
)

// Path-safety helpers shared by every Source. Two layers:
//
//   - validateDestination — used by Fetch. Refuses relative paths,
//     `/` and the empty string, any path at or under a protected system
//     subtree (sys/fs.IsUnderProtectedPrefix — deny-by-default at ANY depth,
//     not just an exact top-level match), and any symlink-rewritten
//     destination (parent chain OR final component) that lands on one. The
//     agent-owned managed roots are the sole exemption.
//   - canWipe — used by Wipe. Strict allow-list on top of the
//     destination check: `/var/lib/power-manage/...`,
//     `/etc/power-manage/...`, or any path previously seen by a
//     successful Fetch (RecordDest). The recorded set is process-local;
//     once the agent restarts only the project-managed prefixes remain
//     wipe-eligible — the safer default after a crash / upgrade.
//
// The allow-list match is intentionally **lexical** (clean path prefix)
// rather than symlink-resolved. The managed roots are agent-owned in real
// deployments — the agent is the only writer there, so a hostile symlink
// would mean the agent itself was compromised, in which case the rest of
// these checks don't matter either. The lexical check also makes the
// helper testable on hosts where /var/lib/power-manage is owned by
// another uid (e.g. a developer machine that ran the install script).

// wipeAllowedRoots are the only path prefixes Wipe will touch in the
// absence of a RecordDest entry. Mirrors the canonical agent state dirs
// documented in install.sh + setup.sh. Trailing slash is required so the
// prefix check can't match a hostile sibling (e.g. `/var/lib/power-manage-evil`).
var wipeAllowedRoots = []string{
	"/var/lib/power-manage/",
	"/etc/power-manage/",
}

// isManagedRoot reports whether clean is at or under one of the agent-owned
// managed roots. These live UNDER protected system prefixes (/etc/power-manage
// is under /etc, /var/lib/power-manage under /var/lib), so the deny-by-default
// subtree check would otherwise refuse the agent's own state dirs. The match is
// lexical with a trailing-slash boundary (so a hostile sibling like
// /etc/power-manage-evil is NOT mistaken for the managed root) — see the file
// header for why agent-owned roots are intentionally not symlink-resolved.
func isManagedRoot(clean string) bool {
	for _, root := range wipeAllowedRoots {
		// Normalise to a trailing-slash boundary regardless of how the entry is
		// written, so a hostile sibling (/etc/power-manage-evil) can never be
		// mistaken for the managed root /etc/power-manage.
		root = strings.TrimSuffix(root, "/") + "/"
		if strings.HasPrefix(clean+"/", root) {
			return true
		}
	}
	return false
}

var (
	recordedDestsMu sync.RWMutex
	recordedDests   = make(map[string]struct{})
)

// validateDestination ensures path is safe to mutate. Returns
// ErrUnsafeDestination wrapping the specific reason; callers branch on
// the sentinel with errors.Is.
func validateDestination(path string) error {
	trim := strings.TrimSpace(path)
	if trim == "" {
		return fmt.Errorf("%w: empty path", ErrUnsafeDestination)
	}
	if !filepath.IsAbs(trim) {
		return fmt.Errorf("%w: %s is not absolute", ErrUnsafeDestination, path)
	}
	clean := filepath.Clean(trim)
	if clean == "/" {
		return fmt.Errorf("%w: %s resolves to /", ErrUnsafeDestination, path)
	}
	// Agent-owned managed roots are accepted lexically and early — before the
	// deny-by-default subtree check (which would refuse them, as they live
	// under /etc and /var/lib) and before symlink resolution (which can hit
	// permission-denied on a root-owned managed dir). See the file header.
	if isManagedRoot(clean) {
		return nil
	}
	// Deny-by-default: refuse any destination at or under a protected system
	// subtree at ANY depth (sys/fs.IsUnderProtectedPrefix), not just the exact
	// top-level dir. The old exact-match IsProtectedPath accepted /etc/cron.d/x,
	// /usr/bin/sshd, /home/<u>/.ssh/... — writing remote content there is root
	// code-exec / privesc, which doc.go promises is impossible.
	if sysfs.IsUnderProtectedPrefix(clean) {
		return fmt.Errorf("%w: %s is under a protected system path", ErrUnsafeDestination, path)
	}

	// Resolve symlinks in the parent chain so a tampered intermediate
	// can't redirect the write to a protected location. Failures with
	// "permission denied" propagate as unsafe — we err on the side of
	// caution rather than write through an opaque ACL.
	if resolved, err := sysfs.ResolveAndValidatePath(trim); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnsafeDestination, path, err)
	} else if sysfs.IsUnderProtectedPrefix(resolved) {
		return fmt.Errorf("%w: %s resolves to protected path %s", ErrUnsafeDestination, path, resolved)
	}

	// ResolveAndValidatePath only walks the parent chain, so a symlink
	// AT the leaf (the user-provided path itself) wouldn't be caught
	// above. Lstat + EvalSymlinks closes that gap for the case where the
	// leaf already exists.
	if fi, lerr := os.Lstat(trim); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		if target, terr := filepath.EvalSymlinks(trim); terr == nil && sysfs.IsUnderProtectedPrefix(target) {
			return fmt.Errorf("%w: %s is a symlink to protected path %s", ErrUnsafeDestination, path, target)
		}
	}
	return nil
}

// canWipe is the stricter guard Wipe uses. Layered on top of
// validateDestination: requires the path to live under one of
// wipeAllowedRoots (lexical prefix) OR to have been previously recorded
// by a successful Fetch via RecordDest.
func canWipe(path string) error {
	trim := strings.TrimSpace(path)
	if trim == "" {
		return fmt.Errorf("%w: empty path", ErrUnsafeDestination)
	}
	if !filepath.IsAbs(trim) {
		return fmt.Errorf("%w: %s is not absolute", ErrUnsafeDestination, path)
	}
	clean := filepath.Clean(trim)
	if clean == "/" {
		return fmt.Errorf("%w: %s resolves to /", ErrUnsafeDestination, path)
	}
	// Managed roots are agent-owned; accept them lexically and skip resolution
	// so the check doesn't fail on hosts where those dirs are owned by another
	// uid (e.g. a dev machine post-install).
	if isManagedRoot(clean) {
		return nil
	}
	// Deny-by-default subtree refusal comes BEFORE the recorded-set check, so a
	// recorded protected path can never jailbreak the guard: a Fetch→RecordDest
	// →Wipe round-trip cannot rm -rf /etc/cron.d/x even if it were somehow
	// recorded (the WS0 fail-open: old exact-match IsProtectedPath let subpaths
	// through here and at the recorded check below).
	if sysfs.IsUnderProtectedPrefix(clean) {
		return fmt.Errorf("%w: %s is under a protected system path", ErrUnsafeDestination, path)
	}

	// Outside the managed roots — require resolution AND prior recording.
	// Recorded set lookup uses both the cleaned form (what RecordDest
	// stores when resolution failed) and the resolved form (the
	// preferred key).
	recordedDestsMu.RLock()
	_, recorded := recordedDests[clean]
	recordedDestsMu.RUnlock()
	if recorded {
		return nil
	}
	if resolved, err := sysfs.ResolveAndValidatePath(trim); err == nil {
		if sysfs.IsUnderProtectedPrefix(resolved) {
			return fmt.Errorf("%w: %s resolves to protected path %s", ErrUnsafeDestination, path, resolved)
		}
		recordedDestsMu.RLock()
		_, recorded = recordedDests[resolved]
		recordedDestsMu.RUnlock()
		if recorded {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s: %v", ErrUnsafeDestination, path, err)
	}

	return fmt.Errorf("%w: %s is not under a managed root and was not recorded", ErrUnsafeDestination, path)
}

// RecordDest registers a destination that a successful Fetch has just
// written to, so a later Wipe in the same process can clean it up even if
// the path lives outside the project-managed prefixes. Safe to call from
// multiple goroutines. Records both the cleaned and resolved forms so a
// later canWipe call matches either way.
func RecordDest(path string) {
	trim := strings.TrimSpace(path)
	if !filepath.IsAbs(trim) {
		return
	}
	clean := filepath.Clean(trim)
	recordedDestsMu.Lock()
	defer recordedDestsMu.Unlock()
	recordedDests[clean] = struct{}{}
	if resolved, err := sysfs.ResolveAndValidatePath(trim); err == nil {
		recordedDests[resolved] = struct{}{}
	}
}

// forgetDest drops a previously-recorded path. Test helper; exported only
// within the package so suite teardown stays hermetic.
func forgetDest(path string) {
	clean := filepath.Clean(strings.TrimSpace(path))
	recordedDestsMu.Lock()
	defer recordedDestsMu.Unlock()
	delete(recordedDests, clean)
	if resolved, err := sysfs.ResolveAndValidatePath(path); err == nil {
		delete(recordedDests, resolved)
	}
}
