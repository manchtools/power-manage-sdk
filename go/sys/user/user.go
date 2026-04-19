// Package user provides user and group management utilities for Linux systems.
//
// User operations (Create, Delete, Modify, Lock, etc.) use sudo for privilege
// escalation. Query operations (Get, Exists, PrimaryGroup) run as the current
// user where possible, falling back to sudo for restricted data like shadow.
package user

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// Info holds the current state of a user account.
type Info struct {
	UID     int
	GID     int
	Comment string
	HomeDir string
	Shell   string
	Groups  []string // supplementary groups (excluding primary)
	Locked  bool
}

// =============================================================================
// User Query Functions
// =============================================================================

// Get retrieves the current state of a user from the system.
func Get(username string) (*Info, error) {
	// Get passwd entry: username:x:uid:gid:comment:home:shell
	out, err := exec.Query("getent", "passwd", username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 7 {
		return nil, fmt.Errorf("invalid passwd entry")
	}

	uid, _ := strconv.Atoi(fields[2])
	gid, _ := strconv.Atoi(fields[3])

	info := &Info{
		UID:     uid,
		GID:     gid,
		Comment: fields[4],
		HomeDir: fields[5],
		Shell:   fields[6],
	}

	// Resolve the primary group name from the GID we already have, so we
	// don't have to shell out to `id -gn` in addition to `id -Gn`.
	var primary string
	if out, err := exec.Query("getent", "group", strconv.Itoa(gid)); err == nil {
		// getent group format: name:passwd:gid:members
		if idx := strings.IndexByte(out, ':'); idx > 0 {
			primary = out[:idx]
		}
	}

	// Get supplementary groups (filter out the primary group).
	if allGroups, err := exec.Query("id", "-Gn", username); err == nil {
		for _, g := range strings.Fields(strings.TrimSpace(allGroups)) {
			if g != primary {
				info.Groups = append(info.Groups, g)
			}
		}
	}

	// Check if account is locked (password field starts with ! or *).
	// Uses sudo because the shadow file is root-only; if sudo -n is not
	// authorized for this caller, leave Locked=false rather than guessing.
	if shadowOut, exit, err := exec.QueryOutput("sudo", "-n", "getent", "shadow", username); err == nil && exit == 0 && shadowOut != "" {
		shadowFields := strings.Split(shadowOut, ":")
		if len(shadowFields) >= 2 {
			passField := shadowFields[1]
			info.Locked = strings.HasPrefix(passField, "!") || strings.HasPrefix(passField, "*")
		}
	}

	return info, nil
}

// Exists checks if a user exists on the system.
func Exists(username string) bool {
	return exec.Check("id", username)
}

// IsValidName checks if a username is valid and safe.
// Valid usernames: start with lowercase letter, contain only [a-z0-9_-], max 32 chars.
func IsValidName(username string) bool {
	if len(username) == 0 || len(username) > 32 {
		return false
	}
	// Must start with a lowercase letter
	if username[0] < 'a' || username[0] > 'z' {
		return false
	}
	// Rest can be lowercase letters, digits, underscores, or hyphens
	for _, c := range username[1:] {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// validateName checks a POSIX-style account name (user or group)
// against IsValidName and returns a descriptive error naming the
// argument kind. Every privileged helper in this package goes
// through it so that (a) a name starting with "-" cannot become a
// useradd/usermod/groupadd flag, and (b) a name containing control
// characters (newline, colon) cannot inject extra chpasswd records.
func validateName(kind, name string) error {
	if !IsValidName(name) {
		return fmt.Errorf("invalid %s %q: must start with a lowercase letter and contain only [a-z0-9_-], max 32 chars", kind, name)
	}
	return nil
}

// validateUsername is a thin wrapper around validateName for
// readability at call sites that specifically handle usernames.
func validateUsername(username string) error { return validateName("username", username) }

// =============================================================================
// User Management Operations
// =============================================================================

// Create creates a new user account with the given options.
// Extra args are passed before the username (e.g., "-m", "-s", "/bin/bash").
// Returns the command result (stdout/stderr/exit code) so callers can
// surface useradd's stderr — important context like "user 'foo' already
// exists" lives there. The Result is non-nil on most failure paths too.
func Create(ctx context.Context, username string, args ...string) (*exec.Result, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	// slices.Clone avoids aliasing the caller's backing array — a
	// bare `append(args, username)` would write into the caller's
	// slice whenever it has spare capacity.
	fullArgs := append(slices.Clone(args), username)
	return exec.Privileged(ctx, "useradd", fullArgs...)
}

// Modify modifies an existing user account.
// Extra args are passed before the username (e.g., "-s", "/bin/zsh").
// Returns the command result so callers can surface usermod's stderr.
func Modify(ctx context.Context, username string, args ...string) (*exec.Result, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	fullArgs := append(slices.Clone(args), username)
	return exec.Privileged(ctx, "usermod", fullArgs...)
}

// Delete removes a user account. If removeHome is true, also removes the home directory.
// Returns the command result so callers can surface userdel's stderr.
func Delete(ctx context.Context, username string, removeHome bool) (*exec.Result, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if removeHome {
		return exec.Privileged(ctx, "userdel", "-r", username)
	}
	return exec.Privileged(ctx, "userdel", username)
}

// Lock locks a user account (usermod -L).
func Lock(ctx context.Context, username string) (*exec.Result, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	return exec.Privileged(ctx, "usermod", "-L", username)
}

// Unlock unlocks a user account (usermod -U).
func Unlock(ctx context.Context, username string) (*exec.Result, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	return exec.Privileged(ctx, "usermod", "-U", username)
}

// =============================================================================
// User Group Queries
// =============================================================================

// PrimaryGroup returns the primary group name for a user.
func PrimaryGroup(username string) (string, error) {
	out, err := exec.Query("id", "-gn", username)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// SupplementaryGroups returns the supplementary groups for a user
// (excluding the primary group).
func SupplementaryGroups(username string) ([]string, error) {
	out, err := exec.Query("id", "-Gn", username)
	if err != nil {
		return nil, err
	}
	groups := strings.Fields(strings.TrimSpace(out))

	// Filter out primary group
	primaryGroup, err := PrimaryGroup(username)
	if err != nil {
		return groups, nil
	}

	var supplementary []string
	for _, g := range groups {
		if g != primaryGroup {
			supplementary = append(supplementary, g)
		}
	}
	return supplementary, nil
}

// =============================================================================
// Password Management
// =============================================================================

// SetPassword sets a user's password using chpasswd.
// Rejects passwords containing newlines — chpasswd reads newline-
// separated "user:password" records from stdin, so a newline in the
// password (or a crafted username) would inject a second record and
// let a caller change an unrelated account. IsValidName already
// eliminates newline-carrying usernames.
func SetPassword(ctx context.Context, username, password string) (*exec.Result, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if strings.ContainsAny(password, "\n\r") {
		return nil, fmt.Errorf("invalid password: must not contain newline or carriage-return characters")
	}
	return exec.PrivilegedWithStdin(ctx, strings.NewReader(fmt.Sprintf("%s:%s", username, password)), "chpasswd")
}

// ExpirePassword forces a user to change their password on next login.
func ExpirePassword(ctx context.Context, username string) (*exec.Result, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	return exec.Privileged(ctx, "chage", "-d", "0", username)
}

// =============================================================================
// User Permission Operations
// =============================================================================

// ChownRecursive changes ownership of a path and all its contents.
// Returns nil result with nil error when owner+group are both empty (no-op).
// The "--" end-of-options separator is passed so an ownership or path
// value that happens to start with "-" cannot be misread as a flag by
// chown.
func ChownRecursive(ctx context.Context, path, owner, group string) (*exec.Result, error) {
	ownership := fs.Ownership(owner, group)
	if ownership == "" {
		return nil, nil
	}
	return exec.Privileged(ctx, "chown", "-R", "--", ownership, path)
}
