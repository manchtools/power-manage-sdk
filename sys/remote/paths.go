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
//     `/` and the empty string, sys/fs.IsProtectedPath matches, and any
//     symlink-rewritten destination (parent chain OR final component)
//     that lands on a protected path.
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
	if sysfs.IsProtectedPath(clean) {
		return fmt.Errorf("%w: %s is a protected system path", ErrUnsafeDestination, path)
	}

	// Resolve symlinks in the parent chain so a tampered intermediate
	// can't redirect the write to a protected location. Failures with
	// "permission denied" propagate as unsafe — we err on the side of
	// caution rather than write through an opaque ACL.
	if resolved, err := sysfs.ResolveAndValidatePath(trim); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnsafeDestination, path, err)
	} else if sysfs.IsProtectedPath(resolved) {
		return fmt.Errorf("%w: %s resolves to protected path %s", ErrUnsafeDestination, path, resolved)
	}

	// ResolveAndValidatePath only walks the parent chain, so a symlink
	// AT the leaf (the user-provided path itself) wouldn't be caught
	// above. Lstat + EvalSymlinks closes that gap for the case where the
	// leaf already exists.
	if fi, lerr := os.Lstat(trim); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		if target, terr := filepath.EvalSymlinks(trim); terr == nil && sysfs.IsProtectedPath(target) {
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
	if sysfs.IsProtectedPath(clean) {
		return fmt.Errorf("%w: %s is a protected system path", ErrUnsafeDestination, path)
	}

	// Lexical allow-list — managed roots are agent-owned; skip resolution
	// so the check doesn't fail on hosts where those dirs are owned by
	// another uid (e.g. a dev machine post-install).
	for _, root := range wipeAllowedRoots {
		if strings.HasPrefix(clean+"/", root) {
			return nil
		}
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
		if sysfs.IsProtectedPath(resolved) {
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
