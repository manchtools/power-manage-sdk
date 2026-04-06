package fs

import "path/filepath"

// protectedPaths are system directories that should never be deleted.
var protectedPaths = map[string]bool{
	"/":      true,
	"/bin":   true,
	"/boot":  true,
	"/dev":   true,
	"/etc":   true,
	"/home":  true,
	"/lib":   true,
	"/lib32": true,
	"/lib64": true,
	"/libx32": true,
	"/media": true,
	"/mnt":   true,
	"/opt":   true,
	"/proc":  true,
	"/root":  true,
	"/run":   true,
	"/sbin":  true,
	"/srv":   true,
	"/sys":   true,
	"/tmp":   true,
	"/usr":   true,
	"/var":   true,
}

// IsProtectedPath returns true if path is a system directory that should
// never be deleted. The path is cleaned before checking.
func IsProtectedPath(path string) bool {
	return protectedPaths[filepath.Clean(path)]
}
