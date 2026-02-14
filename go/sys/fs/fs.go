// Package fs provides privileged filesystem operations for Linux system management.
//
// All write, ownership, and permission operations use sudo for privilege
// escalation. Read operations also use sudo to access files in restricted
// directories (e.g. /etc/sudoers.d on Fedora is mode 0750).
package fs

import (
	"context"
	"fmt"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

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
	out, err := exec.Query("stat", "-c", "%U:%G", path)
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

// WriteFile writes content to a file using sudo tee.
// This is the basic building block for privileged file writes.
func WriteFile(ctx context.Context, path, content string) error {
	_, err := exec.SudoWithStdin(ctx, strings.NewReader(content), "tee", path)
	return err
}

// SetMode sets the file mode (permissions) using sudo chmod.
// mode should be an octal string like "0644".
// Does nothing if mode is empty.
func SetMode(ctx context.Context, path, mode string) error {
	if mode == "" {
		return nil
	}
	_, err := exec.Sudo(ctx, "chmod", mode, path)
	return err
}

// SetOwnership sets the file owner and group using sudo chown.
// Either owner or group can be empty, but not both.
// Does nothing if both are empty.
func SetOwnership(ctx context.Context, path, owner, group string) error {
	ownership := Ownership(owner, group)
	if ownership == "" {
		return nil
	}
	_, err := exec.Sudo(ctx, "chown", ownership, path)
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

// WriteFileAtomic writes content to a file atomically with the specified
// permissions. It writes to a temp file first, sets permissions, then moves
// it into place. This prevents TOCTOU race conditions.
func WriteFileAtomic(ctx context.Context, path, content, mode, owner, group string) error {
	tmpPath := path + ".pm-tmp"

	// Write content to temp file
	if err := WriteFile(ctx, tmpPath, content); err != nil {
		Remove(ctx, tmpPath) // cleanup
		return fmt.Errorf("write file %s: %w", tmpPath, err)
	}

	// Set permissions on temp file before moving
	if err := SetPermissions(ctx, tmpPath, mode, owner, group); err != nil {
		Remove(ctx, tmpPath) // cleanup
		return err
	}

	// Atomic move into place
	if _, err := exec.Sudo(ctx, "mv", "-f", tmpPath, path); err != nil {
		Remove(ctx, tmpPath) // cleanup
		return fmt.Errorf("move file into place: %w", err)
	}

	return nil
}

// =============================================================================
// File Read Operations
// =============================================================================

// ReadFile reads a file's contents using sudo cat.
// Returns the content with trailing newline preserved (matching what's on disk).
// If the file doesn't exist, returns an empty string and nil error.
func ReadFile(ctx context.Context, path string) (string, error) {
	result, err := exec.Sudo(ctx, "cat", path)
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

// FileExists checks whether a path exists using sudo test -e.
// This is needed for paths in directories not readable by the current user
// (e.g. /etc/sudoers.d is mode 0750 on Fedora/RHEL).
func FileExists(ctx context.Context, path string) bool {
	_, err := exec.Sudo(ctx, "sh", "-c", "test -e "+path)
	return err == nil
}

// =============================================================================
// File Delete Operations
// =============================================================================

// Remove removes a file using sudo rm -f.
// This is a best-effort operation that doesn't return errors.
func Remove(ctx context.Context, path string) {
	exec.Sudo(ctx, "rm", "-f", path)
}

// RemoveStrict removes a file using sudo rm -f and returns any error.
func RemoveStrict(ctx context.Context, path string) error {
	_, err := exec.Sudo(ctx, "rm", "-f", path)
	return err
}

// =============================================================================
// Directory Operations
// =============================================================================

// Mkdir creates a directory using sudo mkdir.
// If recursive is true, parent directories are created as needed (-p flag).
func Mkdir(ctx context.Context, path string, recursive bool) error {
	args := []string{}
	if recursive {
		args = append(args, "-p")
	}
	args = append(args, path)
	_, err := exec.Sudo(ctx, "mkdir", args...)
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

// RemoveDir removes a directory and its contents using sudo rm -rf.
func RemoveDir(ctx context.Context, path string) error {
	_, err := exec.Sudo(ctx, "rm", "-rf", path)
	return err
}

// =============================================================================
// Copy Operations
// =============================================================================

// CopyFile copies a file from src to dst using sudo cp.
func CopyFile(ctx context.Context, src, dst string) error {
	_, err := exec.Sudo(ctx, "cp", src, dst)
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
