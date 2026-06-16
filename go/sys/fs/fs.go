// Package fs provides privileged filesystem operations for Linux system management.
//
// All write, ownership, and permission operations escalate through the
// configured privilege backend (sudo or doas — see exec.SetPrivilegeBackend).
// Read operations also escalate via the backend to access files in restricted
// directories (e.g. /etc/sudoers.d on Fedora is mode 0750).
package fs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// statQueryTimeout caps the context-less GetOwnership call so a hung
// stat (e.g. against an NFS server that has gone away) cannot pin
// the calling goroutine indefinitely. F023.
const statQueryTimeout = 10 * time.Second

// ErrInvalidPath is returned by ValidatePath when the supplied path
// would be unsafe to pass as a positional argument to a privileged
// command (empty, contains a NUL byte, or starts with `-` and would
// be interpreted as an option flag).
var ErrInvalidPath = errors.New("invalid filesystem path")

// ValidatePath rejects paths that would be unsafe to pass through
// `exec.Privileged` as positional arguments. The checks are
// intentionally minimal — no symlink resolution, no allowlisting of
// roots — so callers that need stricter semantics can layer them on
// top.
//
//   - empty → ErrInvalidPath (a Privileged call with an empty argv
//     entry collapses verb + path and accidentally runs `rm -f`
//     against the cwd, etc.)
//   - NUL byte → ErrInvalidPath (the system call interprets NUL as
//     string termination; a NUL inside the path lets an attacker
//     smuggle a different path past higher-level filters)
//   - leading `-` → ErrInvalidPath (would be parsed as a flag by
//     `rm`, `chmod`, `chown`, `mkdir`, etc. — even with a `--`
//     end-of-options separator some tools still treat it as an
//     option in edge versions)
//
// Audit finding #10 called out path inputs lacking consistent
// validation across fs.go's exported surface; this is the central
// chokepoint every privileged file op should call before exec.
func ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("%w: path is empty", ErrInvalidPath)
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%w: path contains NUL byte", ErrInvalidPath)
	}
	if strings.HasPrefix(path, "-") {
		return fmt.Errorf("%w: path %q begins with '-' (would be interpreted as an option flag)", ErrInvalidPath, path)
	}
	return nil
}

// =============================================================================
// Ownership Utilities
// =============================================================================

// Ownership constructs an "owner:group" string for chown commands.
// If only owner is provided, returns "owner". If only group is provided,
// returns ":group". If both are provided, returns "owner:group".
// Returns empty string if both are empty.
func Ownership(owner, group string) string {
	if owner == "" && group == "" {
		return ""
	}
	if group == "" {
		return owner
	}
	if owner == "" {
		return ":" + group
	}
	return owner + ":" + group
}

// GetOwnership retrieves the current owner:group of a file using stat.
// Returns empty strings if the file doesn't exist or can't be read.
func GetOwnership(path string) (owner, group string) {
	ctx, cancel := context.WithTimeout(context.Background(), statQueryTimeout)
	defer cancel()
	out, err := exec.QueryCtx(ctx, "stat", "-c", "%U:%G", "--", path)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(strings.TrimSpace(out), ":")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return "", ""
}

// =============================================================================
// File Write Operations
// =============================================================================

// WriteFile writes content to a file via the privilege backend (tee).
// This is the basic building block for privileged file writes.
func WriteFile(ctx context.Context, path, content string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	_, err := exec.PrivilegedWithStdin(ctx, strings.NewReader(content), "tee", "--", path)
	return err
}

// SetMode sets the file mode (permissions) via the privilege backend (chmod).
// mode should be an octal string like "0644".
// Does nothing if mode is empty.
func SetMode(ctx context.Context, path, mode string) error {
	if mode == "" {
		return nil
	}
	if err := ValidatePath(path); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "chmod", mode, "--", path)
	return err
}

// SetOwnershipRecursive changes ownership of a path and all its
// contents via the privilege backend (chown -R). Returns (nil, nil)
// when both owner and group are empty (no-op). The "--" end-of-
// options separator is passed so an ownership or path value that
// happens to start with "-" cannot be misread as a chown flag.
//
// This used to live in sys/user as ChownRecursive; the SDK tech-debt
// audit (F018) moved it here because it operates on any path, not on
// a user account. The user.ChownRecursive function is now a thin
// deprecated alias that forwards here.
func SetOwnershipRecursive(ctx context.Context, path, owner, group string) (*exec.Result, error) {
	ownership := Ownership(owner, group)
	if ownership == "" {
		return nil, nil
	}
	return exec.Privileged(ctx, "chown", "-R", "--", ownership, path)
}

// SetOwnership sets the file owner and group via the privilege backend (chown).
// Either owner or group can be empty, but not both.
// Does nothing if both are empty.
func SetOwnership(ctx context.Context, path, owner, group string) error {
	ownership := Ownership(owner, group)
	if ownership == "" {
		return nil
	}
	if err := ValidatePath(path); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "chown", "--", ownership, path)
	return err
}

// SetPermissions sets both mode and ownership on a file.
// This is a convenience function that calls SetMode and SetOwnership.
func SetPermissions(ctx context.Context, path, mode, owner, group string) error {
	if mode != "" {
		if err := SetMode(ctx, path, mode); err != nil {
			return fmt.Errorf("chmod: %w", err)
		}
	}
	if owner != "" || group != "" {
		if err := SetOwnership(ctx, path, owner, group); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
	}
	return nil
}

// parseFileMode parses an octal mode string ("0644", "640") into an
// os.FileMode. An empty string defaults to 0644 (the conventional mode
// for a managed config file), so the resulting inode always carries a
// deterministic mode rather than depending on the process umask.
func parseFileMode(mode string) (os.FileMode, error) {
	if mode == "" {
		return 0o644, nil
	}
	v, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid file mode %q: %w", mode, err)
	}
	return os.FileMode(v), nil
}

// WriteFileAtomic writes content to a file with the specified permissions
// and ownership, atomically.
//
// When the active privilege backend is Root — i.e. the process is already
// root, which is how the deployed agent runs — the write takes the
// TOCTOU-safe, fd-based path (writeFileAtomicRoot): a random-suffix
// same-directory temp opened O_NOFOLLOW, fchmod'd, fsync'd, renamed into
// place, then chowned through an O_NOFOLLOW fd. This closes WS6 #2: the
// previous implementation tee'd content to a PREDICTABLE temp path
// (path + ".pm-tmp"), and because `tee` follows symlinks a local attacker
// who could create entries in the target directory could pre-plant
// `<target>.pm-tmp` as a symlink and redirect the root agent's write to
// an arbitrary file — a root arbitrary-file-write privesc.
//
// When the backend is sudo/doas (a non-root caller, e.g. CI integration
// or a dev tool), the escalated path is used: it cannot openat as root,
// so it shells the write through the privilege backend as before. That
// path is NOT symlink-safe, but the security-relevant consumer — the root
// agent — never takes it.
func WriteFileAtomic(ctx context.Context, path, content, mode, owner, group string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidatePath(path); err != nil {
		return err
	}
	if exec.CurrentPrivilegeBackend() == exec.Direct {
		return writeFileAtomicRoot(path, content, mode, owner, group)
	}
	return writeFileAtomicEscalated(ctx, path, content, mode, owner, group)
}

// writeFileAtomicRoot is the fd-based, symlink-safe path (WS6 #2). Runs
// the syscalls directly with the process's own (root) privilege.
func writeFileAtomicRoot(path, content, mode, owner, group string) error {
	perm, err := parseFileMode(mode)
	if err != nil {
		return err
	}
	if err := SafeReplaceFile(path, []byte(content), perm, true); err != nil {
		return fmt.Errorf("write file %s: %w", path, err)
	}
	if owner != "" || group != "" {
		uid, gid, err := ResolveOwnership(owner, group)
		if err != nil {
			return err
		}
		if err := FchownNoFollow(path, uid, gid); err != nil {
			return fmt.Errorf("set ownership on %s: %w", path, err)
		}
	}
	return nil
}

// writeFileAtomicEscalated is the legacy privilege-backend (sudo/doas)
// path for non-root callers. Predictable temp + `tee`/`mv`; not
// symlink-safe (see WriteFileAtomic's doc for why that is acceptable).
func writeFileAtomicEscalated(ctx context.Context, path, content, mode, owner, group string) error {
	tmpPath := path + ".pm-tmp"
	if err := WriteFile(ctx, tmpPath, content); err != nil {
		Remove(ctx, tmpPath)
		return fmt.Errorf("write file %s: %w", tmpPath, err)
	}
	if err := SetPermissions(ctx, tmpPath, mode, owner, group); err != nil {
		Remove(ctx, tmpPath)
		return err
	}
	if _, err := exec.Privileged(ctx, "mv", "-f", "--", tmpPath, path); err != nil {
		Remove(ctx, tmpPath)
		return fmt.Errorf("move file into place: %w", err)
	}
	return nil
}

// =============================================================================
// File Read Operations
// =============================================================================

// ReadFile reads a file's contents via the privilege backend (cat).
// Returns the content with trailing newline preserved (matching what's on disk).
// If the file doesn't exist, returns an empty string and nil error.
func ReadFile(ctx context.Context, path string) (string, error) {
	if err := ValidatePath(path); err != nil {
		return "", err
	}
	result, err := exec.Privileged(ctx, "cat", "--", path)
	if err != nil {
		if result != nil && strings.Contains(result.Stderr, "No such file") {
			return "", nil
		}
		return "", err
	}
	// go-cmd splits output into lines and joins with "\n", which strips the
	// trailing newline that text files have. Restore it so content comparisons
	// work correctly.
	if result.Stdout != "" {
		return result.Stdout + "\n", nil
	}
	return result.Stdout, nil
}

// FileExists checks whether a path exists via the privilege backend (test -e).
// This is needed for paths in directories not readable by the current user
// (e.g. /etc/sudoers.d is mode 0750 on Fedora/RHEL).
func FileExists(ctx context.Context, path string) bool {
	_, err := exec.Privileged(ctx, "test", "-e", path)
	return err == nil
}

// =============================================================================
// File Delete Operations
// =============================================================================

// Remove removes a file via the privilege backend (rm -f).
// This is a best-effort operation that doesn't return errors.
//
// Best-effort here means we don't surface errors back to the caller,
// not that we skip safety: path validation runs and we silently bail
// when ValidatePath rejects the input — matching the function's
// existing fire-and-forget contract while still refusing to invoke
// rm on a `-flag`-shaped path.
func Remove(ctx context.Context, path string) {
	if err := ValidatePath(path); err != nil {
		return
	}
	_, _ = exec.Privileged(ctx, "rm", "-f", "--", path)
}

// RemoveStrict removes a file via the privilege backend (rm -f) and returns any error.
//
// The `--` end-of-options separator is mandatory here: without it, a
// path that starts with `-` would be interpreted by `rm` as a flag.
// ValidatePath also rejects leading-`-` inputs at the boundary, so
// this is belt-and-braces.
func RemoveStrict(ctx context.Context, path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "rm", "-f", "--", path)
	return err
}

// =============================================================================
// Directory Operations
// =============================================================================

// Mkdir creates a directory via the privilege backend (mkdir).
// If recursive is true, parent directories are created as needed (-p flag).
func Mkdir(ctx context.Context, path string, recursive bool) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	args := []string{}
	if recursive {
		args = append(args, "-p")
	}
	args = append(args, "--", path)
	_, err := exec.Privileged(ctx, "mkdir", args...)
	return err
}

// MkdirWithPermissions creates a directory with the specified
// mode and ownership. If recursive is true, parent directories are created.
func MkdirWithPermissions(ctx context.Context, path, mode, owner, group string, recursive bool) error {
	if err := Mkdir(ctx, path, recursive); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	if err := SetPermissions(ctx, path, mode, owner, group); err != nil {
		return err
	}
	return nil
}

// dangerousPaths are paths that must never be removed.
var dangerousPaths = map[string]bool{
	"/":      true,
	"/boot":  true,
	"/dev":   true,
	"/etc":   true,
	"/proc":  true,
	"/run":   true,
	"/sys":   true,
	"/usr":   true,
	"/var":   true,
	"/bin":   true,
	"/sbin":  true,
	"/lib":   true,
	"/lib64": true,
	"/home":  true,
	"/root":  true,
}

// RemoveDir removes a directory and its contents WITHOUT following any
// symlink (intermediate component, leaf, or descendant) and refuses any
// target at or under a security-relevant system prefix.
//
// Two hardenings over the previous `rm -rf` implementation:
//
//   - Deny-by-default (WS6 #12): the old guard was a top-level-only
//     exact-match denylist, so `/etc/sudoers.d`, `/home/alice`,
//     `/var/lib/anything` slipped through to a root `rm -rf`.
//     IsUnderProtectedPrefix refuses the whole subtree of every
//     protected root.
//   - Symlink-refusing fd-anchored delete (WS6 #4): `rm -rf <path>`
//     re-resolves the path, so a component swapped for a symlink after
//     validation could redirect the recursive delete. removeDirSecure
//     walks the path by openat(O_NOFOLLOW) handles, never re-resolving a
//     string, so a swapped component aborts the operation.
//
// The agent (root) reuses IsUnderProtectedPrefix in its directory action
// to additionally require the target be under a configured managed prefix
// (a true allowlist); this SDK guard is the defense-in-depth floor.
func RemoveDir(ctx context.Context, path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("path must be absolute: %s", path)
	}
	// Deny-by-default applies regardless of backend (WS6 #12).
	if IsUnderProtectedPrefix(clean) {
		return fmt.Errorf("refusing to remove protected path: %s", clean)
	}
	// Root (the deployed agent): symlink-refusing fd-anchored delete
	// (WS6 #4). Non-root callers cannot openat as root, so they fall back
	// to the privilege-backend `rm -rf` (not symlink-safe, but not the
	// root agent's path).
	if exec.CurrentPrivilegeBackend() == exec.Direct {
		return removeDirSecure(ctx, clean)
	}
	_, err := exec.Privileged(ctx, "rm", "-rf", "--", clean)
	return err
}

// =============================================================================
// Copy Operations
// =============================================================================

// CopyFile copies a file from src to dst via the privilege backend (cp).
func CopyFile(ctx context.Context, src, dst string) error {
	if err := ValidatePath(src); err != nil {
		return err
	}
	if err := ValidatePath(dst); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "cp", "--", src, dst)
	return err
}

// CopyFileWithPermissions copies a file and sets the specified permissions.
func CopyFileWithPermissions(ctx context.Context, src, dst, mode, owner, group string) error {
	if err := CopyFile(ctx, src, dst); err != nil {
		return fmt.Errorf("copy file: %w", err)
	}
	if err := SetPermissions(ctx, dst, mode, owner, group); err != nil {
		return err
	}
	return nil
}
