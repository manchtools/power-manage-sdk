package fs

import (
	"fmt"
	"os"
	"path/filepath"
)

// ResolveAndValidatePath resolves symlinks in the parent directory of the given
// path and returns the cleaned, resolved absolute path. This prevents symlink
// traversal attacks where a symlink could redirect writes to sensitive locations.
func ResolveAndValidatePath(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("path must be absolute: %s", path)
	}

	// Walk up from the target file to find the first existing parent directory.
	// This handles cases where intermediate directories don't exist yet.
	dir := filepath.Dir(clean)
	var existingParent, missingTail string

	for dir != "/" && dir != "." {
		if _, err := os.Stat(dir); err == nil {
			existingParent = dir
			break
		} else if os.IsNotExist(err) {
			missingTail = filepath.Join(filepath.Base(dir), missingTail)
			dir = filepath.Dir(dir)
		} else {
			// Permission denied or other error — reject the path.
			return "", fmt.Errorf("cannot stat %s: %w", dir, err)
		}
	}

	if existingParent == "" {
		existingParent = "/"
	}

	// Resolve symlinks only in the existing portion of the path.
	resolved, err := filepath.EvalSymlinks(existingParent)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks in %s: %w", existingParent, err)
	}

	// Rebuild the full path with resolved parent + missing components + filename.
	if missingTail != "" {
		return filepath.Join(resolved, missingTail, filepath.Base(clean)), nil
	}
	return filepath.Join(resolved, filepath.Base(clean)), nil
}
