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

// =============================================================================
// User Management Operations
// =============================================================================

// Create creates a new user account with the given options.
// Extra args are passed before the username (e.g., "-m", "-s", "/bin/bash").
func Create(ctx context.Context, username string, args ...string) error {
	fullArgs := append(args, username)
	_, err := exec.Sudo(ctx, "useradd", fullArgs...)
	return err
}

// Modify modifies an existing user account.
// Extra args are passed before the username (e.g., "-s", "/bin/zsh").
func Modify(ctx context.Context, username string, args ...string) error {
	fullArgs := append(args, username)
	_, err := exec.Sudo(ctx, "usermod", fullArgs...)
	return err
}

// Delete removes a user account. If removeHome is true, also removes the home directory.
func Delete(ctx context.Context, username string, removeHome bool) error {
	if removeHome {
		_, err := exec.Sudo(ctx, "userdel", "-r", username)
		return err
	}
	_, err := exec.Sudo(ctx, "userdel", username)
	return err
}

// Lock locks a user account (usermod -L).
func Lock(ctx context.Context, username string) error {
	_, err := exec.Sudo(ctx, "usermod", "-L", username)
	return err
}

// Unlock unlocks a user account (usermod -U).
func Unlock(ctx context.Context, username string) error {
	_, err := exec.Sudo(ctx, "usermod", "-U", username)
	return err
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
func SetPassword(ctx context.Context, username, password string) error {
	_, err := exec.SudoWithStdin(ctx, strings.NewReader(fmt.Sprintf("%s:%s", username, password)), "chpasswd")
	return err
}

// ExpirePassword forces a user to change their password on next login.
func ExpirePassword(ctx context.Context, username string) error {
	_, err := exec.Sudo(ctx, "chage", "-d", "0", username)
	return err
}

// =============================================================================
// User Permission Operations
// =============================================================================

// ChownRecursive changes ownership of a path and all its contents.
func ChownRecursive(ctx context.Context, path, owner, group string) error {
	ownership := fs.Ownership(owner, group)
	if ownership == "" {
		return nil
	}
	_, err := exec.Sudo(ctx, "chown", "-R", ownership, path)
	return err
}
