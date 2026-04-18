// Package user provides user and group management utilities for Linux systems.
//
// User operations (Create, Delete, Modify, Lock, etc.) use sudo for privilege
// escalation. Query operations (Get, Exists, PrimaryGroup) run as the current
// user where possible, falling back to sudo for restricted data like shadow.
package user

import (
	"context"
	"fmt"
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

	// Get supplementary groups
	if allGroups, err := exec.Query("id", "-Gn", username); err == nil {
		groups := strings.Fields(strings.TrimSpace(allGroups))
		// Filter out the primary group
		if primaryGroup, err := exec.Query("id", "-gn", username); err == nil {
			primary := strings.TrimSpace(primaryGroup)
			for _, g := range groups {
				if g != primary {
					info.Groups = append(info.Groups, g)
				}
			}
		}
	}

	// Check if account is locked (password field starts with ! or *)
	// Use sudo to read shadow file
	if shadowOut, _, _ := exec.QueryOutput("sudo", "-n", "getent", "shadow", username); shadowOut != "" {
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

// validateUsername returns a descriptive error if the name fails
// IsValidName. Every privileged user-management helper in this package
// goes through this guard so that (a) a username starting with "-"
// cannot become a useradd/usermod flag, and (b) a username containing
// control characters (newline, colon) cannot inject extra chpasswd
// lines.
func validateUsername(username string) error {
	if !IsValidName(username) {
		return fmt.Errorf("invalid username %q: must start with a lowercase letter and contain only [a-z0-9_-], max 32 chars", username)
	}
	return nil
}

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
	fullArgs := append(args, username)
	return exec.Privileged(ctx, "useradd", fullArgs...)
}

// Modify modifies an existing user account.
// Extra args are passed before the username (e.g., "-s", "/bin/zsh").
// Returns the command result so callers can surface usermod's stderr.
func Modify(ctx context.Context, username string, args ...string) (*exec.Result, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	fullArgs := append(args, username)
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
