package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// MembersMatch reports whether two member lists contain the same set of names,
// ignoring order and duplicates. A pure helper for group-membership
// reconciliation (compare desired vs. GroupMembers); the caller decides what to
// do about a mismatch.
func MembersMatch(a, b []string) bool {
	set := func(xs []string) map[string]struct{} {
		m := make(map[string]struct{}, len(xs))
		for _, x := range xs {
			m[x] = struct{}{}
		}
		return m
	}
	sa, sb := set(a), set(b)
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if _, ok := sb[k]; !ok {
			return false
		}
	}
	return true
}

// GroupExists reports whether a group exists.
func (u *shadowUtils) GroupExists(ctx context.Context, name string) (bool, error) {
	if err := validateName("group name", name); err != nil {
		return false, err
	}
	ctx, cancel := ensureCtx(ctx)
	defer cancel()
	res, err := u.exec(ctx, exec.Command{Name: "getent", Args: []string{"group", name}})
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// GroupMembers returns a group's members, or nil if the group has none / does
// not exist.
func (u *shadowUtils) GroupMembers(ctx context.Context, name string) ([]string, error) {
	if err := validateName("group name", name); err != nil {
		return nil, err
	}
	ctx, cancel := ensureCtx(ctx)
	defer cancel()
	out, err := u.query(ctx, "getent", "group", name)
	if err != nil {
		// getent exits 2 for "group not found" — a clean absence, reported as a
		// wrapped os.ErrNotExist so a caller can tell it apart from "group exists
		// with no members" ((nil, nil) below). Any OTHER failure (Runner /
		// escalation / a different exit) is real and propagates — never silently
		// read as "no members".
		var ce *exec.CommandError
		if errors.As(err, &ce) && ce.ExitCode == 2 {
			return nil, fmt.Errorf("group %q: %w", name, os.ErrNotExist)
		}
		return nil, err
	}
	fields := strings.Split(out, ":")
	if len(fields) < 4 || fields[3] == "" {
		return nil, nil
	}
	// Filter empty entries defensively (a stray "a,,b" must not yield a "").
	raw := strings.Split(fields[3], ",")
	members := make([]string, 0, len(raw))
	for _, m := range raw {
		if m != "" {
			members = append(members, m)
		}
	}
	if len(members) == 0 {
		return nil, nil
	}
	return members, nil
}

// GroupCreate creates a new group.
func (u *shadowUtils) GroupCreate(ctx context.Context, name string, opts GroupCreateOptions) error {
	if err := validateName("group name", name); err != nil {
		return err
	}
	if opts.GID < 0 {
		return fmt.Errorf("invalid GID %d: must be >= 0 (0 = auto-assign)", opts.GID)
	}
	args := make([]string, 0, 4)
	if opts.GID > 0 {
		args = append(args, "-g", strconv.Itoa(opts.GID))
	}
	if opts.System {
		args = append(args, "-r")
	}
	args = append(args, name)
	return u.run(ctx, "groupadd", args...)
}

// GroupDelete deletes a group.
func (u *shadowUtils) GroupDelete(ctx context.Context, name string) error {
	if err := validateName("group name", name); err != nil {
		return err
	}
	return u.run(ctx, "groupdel", name)
}

// GroupEnsure creates a group if it does not already exist (no-op when present).
func (u *shadowUtils) GroupEnsure(ctx context.Context, name string) error {
	exists, err := u.GroupExists(ctx, name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return u.GroupCreate(ctx, name, GroupCreateOptions{})
}

// AddToGroup adds a user to a supplementary group (usermod -aG).
func (u *shadowUtils) AddToGroup(ctx context.Context, name, group string) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	if err := validateName("group name", group); err != nil {
		return err
	}
	return u.run(ctx, "usermod", "-aG", group, name)
}

// RemoveFromGroup removes a user from a supplementary group (gpasswd -d).
func (u *shadowUtils) RemoveFromGroup(ctx context.Context, name, group string) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	if err := validateName("group name", group); err != nil {
		return err
	}
	return u.run(ctx, "gpasswd", "-d", name, group)
}
