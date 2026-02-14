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
	return exec.Check("getent", "group", name)
}

// GroupMembers returns the members of a group.
// Returns nil if the group doesn't exist or has no members.
func GroupMembers(name string) []string {
	out, err := exec.Query("getent", "group", name)
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
func GroupCreate(ctx context.Context, name string, args ...string) error {
	fullArgs := append(args, name)
	_, err := exec.Sudo(ctx, "groupadd", fullArgs...)
	return err
}

// GroupDelete deletes a group.
func GroupDelete(ctx context.Context, name string) error {
	_, err := exec.Sudo(ctx, "groupdel", name)
	return err
}

// GroupEnsureExists creates a group if it doesn't already exist.
func GroupEnsureExists(ctx context.Context, name string) error {
	if GroupExists(name) {
		return nil
	}
	return GroupCreate(ctx, name)
}

// =============================================================================
// Group Membership Operations
// =============================================================================

// GroupAddUser adds a user to a supplementary group.
func GroupAddUser(ctx context.Context, username, groupName string) error {
	_, err := exec.Sudo(ctx, "usermod", "-aG", groupName, username)
	return err
}

// GroupRemoveUser removes a user from a supplementary group.
func GroupRemoveUser(ctx context.Context, username, groupName string) error {
	_, err := exec.Sudo(ctx, "gpasswd", "-d", username, groupName)
	return err
}
