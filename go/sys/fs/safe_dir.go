package fs

import (
	"fmt"
	"os"
)

// AssertRealDir verifies that path is a real directory and not a
// symlink (or any other non-directory). Callers use it as a pre-flight
// guard before running a privileged, path-based chmod/chown on a
// directory an untrusted user may control — the canonical case being
// ~/.ssh, which is owned by the target user. Such a user can plant the
// path as a symlink to an arbitrary location (e.g. /etc); a root-run
// chmod/chown would then dereference it and act on the target, a TOCTOU
// privilege escalation. Refusing a symlinked path removes that class.
//
// It uses Lstat, so the symlink itself — not its target — is inspected.
// It does not escalate privileges: a stat is read-only, and the agent
// already runs with enough privilege to read the path's metadata.
func AssertRealDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat dir %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %s is a symlink; refusing to dereference it", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("path %s is not a directory", path)
	}
	return nil
}
