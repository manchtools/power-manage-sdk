package fs

import (
	"path/filepath"
	"strings"
)

// IsProtectedPath returns true if path is a system directory that should
// never be deleted. The path is cleaned and resolved to absolute before checking.
// This uses the same set as dangerousPaths (used by RemoveDir) plus additional
// top-level directories.
func IsProtectedPath(path string) bool {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		abs, err := filepath.Abs(clean)
		if err != nil {
			return true // err on the side of caution
		}
		clean = abs
	}
	return dangerousPaths[clean] || extraProtectedPaths[clean]
}

// extraProtectedPaths extends dangerousPaths with additional top-level
// directories that IsProtectedPath should guard but RemoveDir does not
// need to check (since they are less critical or already covered).
var extraProtectedPaths = map[string]bool{
	"/lib32":  true,
	"/libx32": true,
	"/media":  true,
	"/mnt":    true,
	"/opt":    true,
	"/srv":    true,
	"/tmp":    true,
	"/snap":   true, // snap-based distributions (Ubuntu)
}

// protectedPrefixRoots are directory subtrees that a managed directory
// delete must NEVER touch at ANY depth. Unlike IsProtectedPath (an exact
// top-level match), IsUnderProtectedPrefix refuses these roots AND
// everything beneath them — so /etc/sudoers.d, /home/alice/.ssh,
// /var/lib/postgresql, /boot/efi, /usr/bin are all refused, closing the
// "one level down slips through to rm -rf" gap (WS6 #12).
//
// The set is deliberately broad: deletion of anything under the OS,
// package-manager, bootloader, persistent-state, or user-home trees is a
// privilege-escalation / data-destruction vector when an attacker can
// influence the target path. /var itself is refused (see
// protectedExactPaths) but /var/log/<app> and /var/cache/<app> are left
// deletable for managed app data; only /var/lib is locked as a subtree.
var protectedPrefixRoots = []string{
	"/etc",
	"/boot",
	"/usr",
	"/home",
	"/root",
	"/var/lib",
	"/bin",
	"/sbin",
	"/lib",
	"/lib64",
	"/lib32",
	"/libx32",
	"/proc",
	"/sys",
	"/dev",
	"/run",
}

// protectedExactPaths are refused only as an exact match — the directory
// itself must never be removed, but children outside the prefix roots
// above remain deletable (e.g. /var is locked, /var/log/<app> is not).
var protectedExactPaths = map[string]bool{
	"/":    true,
	"/var": true,
}

// IsUnderProtectedPrefix reports whether path is at or under a
// security-relevant system prefix that a managed directory delete must
// refuse. The path is cleaned and resolved to absolute before checking,
// so traversal tricks (/etc/../etc/sudoers.d) and relative inputs cannot
// dodge the guard. This is the deny-by-default predicate RemoveDir uses
// and that the agent's directory action reuses (WS6 #4, #12).
func IsUnderProtectedPrefix(path string) bool {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		abs, err := filepath.Abs(clean)
		if err != nil {
			return true // err on the side of caution
		}
		clean = abs
	}
	if protectedExactPaths[clean] {
		return true
	}
	for _, root := range protectedPrefixRoots {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}
