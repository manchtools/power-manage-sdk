package fs

import "path/filepath"

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
}
