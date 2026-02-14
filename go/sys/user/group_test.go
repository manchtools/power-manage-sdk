//go:build integration

package user_test

import (
	"context"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/user"
)

func testGroupName(suffix string) string {
	return testUsername("g" + suffix)
}

func cleanupGroup(t *testing.T, name string) {
	t.Helper()
	ctx := context.Background()
	exec.Sudo(ctx, "groupdel", name)
}

func TestGroupCreate(t *testing.T) {
	ctx := context.Background()
	name := testGroupName("cr")
	defer cleanupGroup(t, name)

	err := user.GroupCreate(ctx, name)
	if err != nil {
		t.Fatalf("GroupCreate failed: %v", err)
	}

	if !user.GroupExists(name) {
		t.Error("group should exist after creation")
	}
}

func TestGroupDelete(t *testing.T) {
	ctx := context.Background()
	name := testGroupName("dl")

	if err := user.GroupCreate(ctx, name); err != nil {
		t.Fatalf("GroupCreate failed: %v", err)
	}

	err := user.GroupDelete(ctx, name)
	if err != nil {
		t.Fatalf("GroupDelete failed: %v", err)
	}

	if user.GroupExists(name) {
		t.Error("group should not exist after deletion")
	}
}

func TestGroupDeleteNonexistent(t *testing.T) {
	ctx := context.Background()
	err := user.GroupDelete(ctx, "pm-nonexistent-group-12345")
	if err == nil {
		t.Fatal("expected error deleting non-existent group")
	}
}

func TestGroupExists(t *testing.T) {
	if !user.GroupExists("root") {
		t.Error("root group should exist")
	}
	if user.GroupExists("pm-nonexistent-group-12345") {
		t.Error("non-existent group should not exist")
	}
}

func TestGroupMembers(t *testing.T) {
	ctx := context.Background()
	groupName := testGroupName("mb")
	userName := testUsername("gm")
	defer cleanupGroup(t, groupName)
	defer cleanupUser(t, userName)

	if err := user.GroupCreate(ctx, groupName); err != nil {
		t.Fatalf("GroupCreate failed: %v", err)
	}
	createTestUser(t, userName)

	if err := user.GroupAddUser(ctx, userName, groupName); err != nil {
		t.Fatalf("GroupAddUser failed: %v", err)
	}

	members := user.GroupMembers(groupName)
	found := false
	for _, m := range members {
		if m == userName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in group members, got %v", userName, members)
	}
}

func TestGroupAddUser(t *testing.T) {
	ctx := context.Background()
	groupName := testGroupName("au")
	userName := testUsername("ga")
	defer cleanupGroup(t, groupName)
	defer cleanupUser(t, userName)

	if err := user.GroupCreate(ctx, groupName); err != nil {
		t.Fatalf("GroupCreate failed: %v", err)
	}
	createTestUser(t, userName)

	if err := user.GroupAddUser(ctx, userName, groupName); err != nil {
		t.Fatalf("GroupAddUser failed: %v", err)
	}

	if !user.GroupHasUser(userName, groupName) {
		t.Error("user should be in group after GroupAddUser")
	}
}

func TestGroupRemoveUser(t *testing.T) {
	ctx := context.Background()
	groupName := testGroupName("ru")
	userName := testUsername("gr")
	defer cleanupGroup(t, groupName)
	defer cleanupUser(t, userName)

	if err := user.GroupCreate(ctx, groupName); err != nil {
		t.Fatalf("GroupCreate failed: %v", err)
	}
	createTestUser(t, userName)

	if err := user.GroupAddUser(ctx, userName, groupName); err != nil {
		t.Fatalf("GroupAddUser failed: %v", err)
	}

	if err := user.GroupRemoveUser(ctx, userName, groupName); err != nil {
		t.Fatalf("GroupRemoveUser failed: %v", err)
	}

	if user.GroupHasUser(userName, groupName) {
		t.Error("user should not be in group after GroupRemoveUser")
	}
}

func TestGroupEnsureExists(t *testing.T) {
	ctx := context.Background()
	name := testGroupName("ee")
	defer cleanupGroup(t, name)

	// Should create
	err := user.GroupEnsureExists(ctx, name)
	if err != nil {
		t.Fatalf("GroupEnsureExists (create) failed: %v", err)
	}
	if !user.GroupExists(name) {
		t.Error("group should exist after ensure")
	}

	// Should be no-op
	err = user.GroupEnsureExists(ctx, name)
	if err != nil {
		t.Fatalf("GroupEnsureExists (no-op) failed: %v", err)
	}
}

func TestGroupHasUser(t *testing.T) {
	ctx := context.Background()
	groupName := testGroupName("hu")
	userName := testUsername("gh")
	defer cleanupGroup(t, groupName)
	defer cleanupUser(t, userName)

	if err := user.GroupCreate(ctx, groupName); err != nil {
		t.Fatalf("GroupCreate failed: %v", err)
	}
	createTestUser(t, userName)

	if user.GroupHasUser(userName, groupName) {
		t.Error("user should not be in group initially")
	}

	if err := user.GroupAddUser(ctx, userName, groupName); err != nil {
		t.Fatalf("GroupAddUser failed: %v", err)
	}

	if !user.GroupHasUser(userName, groupName) {
		t.Error("user should be in group after add")
	}
}

func TestGroupMembersMatch(t *testing.T) {
	ctx := context.Background()
	groupName := testGroupName("mm")
	user1 := testUsername("m1")
	user2 := testUsername("m2")
	defer cleanupGroup(t, groupName)
	defer cleanupUser(t, user1)
	defer cleanupUser(t, user2)

	if err := user.GroupCreate(ctx, groupName); err != nil {
		t.Fatalf("GroupCreate failed: %v", err)
	}
	createTestUser(t, user1)
	createTestUser(t, user2)

	// Empty group vs empty desired
	if !user.GroupMembersMatch(groupName, []string{}) {
		t.Error("empty group should match empty desired list")
	}

	// Add users
	if err := user.GroupAddUser(ctx, user1, groupName); err != nil {
		t.Fatalf("GroupAddUser failed: %v", err)
	}
	if err := user.GroupAddUser(ctx, user2, groupName); err != nil {
		t.Fatalf("GroupAddUser failed: %v", err)
	}

	// Should match (order independent)
	if !user.GroupMembersMatch(groupName, []string{user2, user1}) {
		t.Error("group members should match desired list (order independent)")
	}

	// Should not match with extra user
	if user.GroupMembersMatch(groupName, []string{user1}) {
		t.Error("should not match when desired list is shorter")
	}

	// Non-existent group with empty desired
	if !user.GroupMembersMatch("pm-nonexistent-group-12345", []string{}) {
		t.Error("non-existent group should match empty desired list")
	}

	// Non-existent group with non-empty desired
	if user.GroupMembersMatch("pm-nonexistent-group-12345", []string{"someone"}) {
		t.Error("non-existent group should not match non-empty desired list")
	}
}
