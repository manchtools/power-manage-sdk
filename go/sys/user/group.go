package user

import (
	"context"
	"sort"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// =============================================================================
// Group Query Functions
// =============================================================================

// GroupExists checks if a group exists on the system.
func GroupExists(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	return exec.CheckCtx(ctx, "getent", "group", name)
}

// GroupMembers returns the members of a group.
// Returns nil if the group doesn't exist or has no members.
func GroupMembers(name string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	out, err := exec.QueryCtx(ctx, "getent", "group", name)
	if err != nil {
		return nil
	}
	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 4 || fields[3] == "" {
		return nil
	}
	return strings.Split(fields[3], ",")
}

// GroupHasUser checks if a user is a member of the specified group.
func GroupHasUser(username, groupName string) bool {
	members := GroupMembers(groupName)
	for _, m := range members {
		if m == username {
			return true
		}
	}
	return false
}

// GroupMembersMatch checks if the current group members match the desired list.
// Comparison is order-independent.
func GroupMembersMatch(groupName string, desiredUsers []string) bool {
	if !GroupExists(groupName) {
		return len(desiredUsers) == 0
	}
	current := GroupMembers(groupName)
	if len(current) != len(desiredUsers) {
		return false
	}

	sortedCurrent := make([]string, len(current))
	copy(sortedCurrent, current)
	sort.Strings(sortedCurrent)

	sortedDesired := make([]string, len(desiredUsers))
	copy(sortedDesired, desiredUsers)
	sort.Strings(sortedDesired)

	for i := range sortedCurrent {
		if sortedCurrent[i] != sortedDesired[i] {
			return false
		}
	}
	return true
}

// =============================================================================
// Group Management Operations
// =============================================================================

// GroupCreate creates a new group.
// Extra args are passed before the group name (e.g., "-g", "1001", "-r").
// Rejects names that would become flags or contain control characters —
// the same IsValidName rules apply because groupadd/usermod parse argv
// identically to useradd.
//
// Returns the command result so callers can surface groupadd's stderr
// — symmetric with the user.Create / user.Modify / user.Delete shape
// (F038 in the SDK tech-debt audit).
func GroupCreate(ctx context.Context, name string, args ...string) (*exec.Result, error) {
	if err := validateName("group name", name); err != nil {
		return nil, err
	}
	// SeparatePositionals inserts a "--" before the group name (and
	// allocates fresh, so the caller's args slice isn't aliased) so a
	// flag-shaped name can't be parsed as a groupadd option.
	fullArgs := exec.SeparatePositionals(args, name)
	return exec.Privileged(ctx, "groupadd", fullArgs...)
}

// GroupDelete deletes a group. See GroupCreate for the result-return
// rationale.
func GroupDelete(ctx context.Context, name string) (*exec.Result, error) {
	if err := validateName("group name", name); err != nil {
		return nil, err
	}
	return exec.Privileged(ctx, "groupdel", exec.SeparatePositionals(nil, name)...)
}

// GroupEnsureExists creates a group if it doesn't already exist.
// Returns (nil, nil) when the group already exists (no command run).
func GroupEnsureExists(ctx context.Context, name string) (*exec.Result, error) {
	if err := validateName("group name", name); err != nil {
		return nil, err
	}
	if GroupExists(name) {
		return nil, nil
	}
	return GroupCreate(ctx, name)
}

// =============================================================================
// Group Membership Operations
// =============================================================================

// GroupAddUser adds a user to a supplementary group. See GroupCreate
// for the result-return rationale.
func GroupAddUser(ctx context.Context, username, groupName string) (*exec.Result, error) {
	if err := validateName("username", username); err != nil {
		return nil, err
	}
	if err := validateName("group name", groupName); err != nil {
		return nil, err
	}
	return exec.Privileged(ctx, "usermod", "-aG", groupName, username)
}

// GroupRemoveUser removes a user from a supplementary group. See
// GroupCreate for the result-return rationale.
func GroupRemoveUser(ctx context.Context, username, groupName string) (*exec.Result, error) {
	if err := validateName("username", username); err != nil {
		return nil, err
	}
	if err := validateName("group name", groupName); err != nil {
		return nil, err
	}
	return exec.Privileged(ctx, "gpasswd", "-d", username, groupName)
}
