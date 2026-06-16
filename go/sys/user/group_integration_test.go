//go:build integration

package user_test

import (
	"context"
	"slices"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/user"
)

func testGroupName(suffix string) string {
	return testUsername("g" + suffix)
}

func cleanupGroup(t *testing.T, m user.Manager, name string) {
	t.Helper()
	_ = m.GroupDelete(context.Background(), name)
}

func TestGroupCreateDelete_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testGroupName("cr")
	defer cleanupGroup(t, m, name)

	if err := m.GroupCreate(ctx, name, user.GroupCreateOptions{}); err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	if ok, err := m.GroupExists(ctx, name); err != nil || !ok {
		t.Fatalf("GroupExists after create = (%v,%v), want (true,nil)", ok, err)
	}
	if err := m.GroupDelete(ctx, name); err != nil {
		t.Fatalf("GroupDelete: %v", err)
	}
	if ok, err := m.GroupExists(ctx, name); err != nil || ok {
		t.Error("group still exists after delete")
	}
}

func TestGroupDeleteNonexistent_Integration(t *testing.T) {
	if err := newManager(t).GroupDelete(context.Background(), "pmnonexistentgrp12345"); err == nil {
		t.Fatal("expected error deleting a non-existent group")
	}
}

func TestGroupExists_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	if ok, err := m.GroupExists(ctx, "root"); err != nil || !ok {
		t.Errorf("GroupExists(root) = (%v,%v), want (true,nil)", ok, err)
	}
	if ok, err := m.GroupExists(ctx, "pmnonexistentgrp12345"); err != nil || ok {
		t.Error("non-existent group reported as existing")
	}
}

func TestGroupMembershipCycle_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	groupName := testGroupName("mb")
	userName := testUsername("gm")
	defer cleanupGroup(t, m, groupName)
	defer cleanupUser(t, m, userName)

	if err := m.GroupCreate(ctx, groupName, user.GroupCreateOptions{}); err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	createTestUser(t, m, userName)

	if err := m.AddToGroup(ctx, userName, groupName); err != nil {
		t.Fatalf("AddToGroup: %v", err)
	}
	members, err := m.GroupMembers(ctx, groupName)
	if err != nil {
		t.Fatalf("GroupMembers: %v", err)
	}
	if !slices.Contains(members, userName) {
		t.Errorf("members %v missing %q after AddToGroup", members, userName)
	}

	if err := m.RemoveFromGroup(ctx, userName, groupName); err != nil {
		t.Fatalf("RemoveFromGroup: %v", err)
	}
	members, err = m.GroupMembers(ctx, groupName)
	if err != nil {
		t.Fatalf("GroupMembers: %v", err)
	}
	if slices.Contains(members, userName) {
		t.Errorf("members %v still contains %q after RemoveFromGroup", members, userName)
	}
}

func TestGroupEnsure_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testGroupName("ee")
	defer cleanupGroup(t, m, name)

	if err := m.GroupEnsure(ctx, name); err != nil {
		t.Fatalf("GroupEnsure (create): %v", err)
	}
	if ok, err := m.GroupExists(ctx, name); err != nil || !ok {
		t.Error("group should exist after ensure")
	}
	if err := m.GroupEnsure(ctx, name); err != nil {
		t.Fatalf("GroupEnsure (no-op): %v", err)
	}
}
