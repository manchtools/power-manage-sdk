//go:build integration

package user_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/user"
)

// newManager builds a real-Runner user.Manager. The integration container runs
// the suite as the non-root power-manage user with passwordless sudo, so the
// escalation backend is Sudo.
func newManager(t *testing.T) user.Manager {
	t.Helper()
	r, err := exec.NewRunner(exec.Sudo)
	if err != nil {
		t.Fatalf("NewRunner(Sudo): %v", err)
	}
	m, err := user.New(user.ShadowUtils, r)
	if err != nil {
		t.Fatalf("user.New: %v", err)
	}
	return m
}

func testUsername(suffix string) string {
	return fmt.Sprintf("pmtest%s%d", suffix, os.Getpid()%10000)
}

func cleanupUser(t *testing.T, m user.Manager, username string) {
	t.Helper()
	_ = m.Delete(context.Background(), username, user.DeleteOptions{RemoveHome: true})
}

func createTestUser(t *testing.T, m user.Manager, username string) {
	t.Helper()
	if err := m.Create(context.Background(), username, user.CreateOptions{CreateHome: true}); err != nil {
		t.Fatalf("create test user %s: %v", username, err)
	}
}

func TestCreate_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("cr")
	defer cleanupUser(t, m, name)

	if err := m.Create(ctx, name, user.CreateOptions{CreateHome: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ok, err := m.Exists(ctx, name); err != nil || !ok {
		t.Fatalf("Exists after create = (%v,%v), want (true,nil)", ok, err)
	}
	info, err := m.Get(ctx, name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if info.Shell != "/bin/bash" {
		t.Errorf("default shell = %s, want /bin/bash", info.Shell)
	}
}

func TestCreateSystemUser_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("sys")
	defer cleanupUser(t, m, name)

	if err := m.Create(ctx, name, user.CreateOptions{System: true}); err != nil {
		t.Fatalf("Create system user: %v", err)
	}
	info, err := m.Get(ctx, name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if info.Shell != "/usr/sbin/nologin" {
		t.Errorf("system shell = %s, want /usr/sbin/nologin", info.Shell)
	}
	if info.UID >= 1000 {
		t.Errorf("system UID = %d, want < 1000", info.UID)
	}
}

func TestGet_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("gt")
	defer cleanupUser(t, m, name)

	if err := m.Create(ctx, name, user.CreateOptions{CreateHome: true, Comment: "Test User"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	info, err := m.Get(ctx, name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if info.UID == 0 {
		t.Error("expected non-zero UID")
	}
	if info.Comment != "Test User" {
		t.Errorf("comment = %q, want 'Test User'", info.Comment)
	}
	if info.HomeDir == "" {
		t.Error("expected non-empty home directory")
	}
	if info.Shell != "/bin/bash" {
		t.Errorf("shell = %s, want /bin/bash", info.Shell)
	}
}

func TestGetNonexistent_Integration(t *testing.T) {
	if _, err := newManager(t).Get(context.Background(), "pmnonexistent12345"); err == nil {
		t.Fatal("expected error for non-existent user")
	}
}

func TestExists_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	if ok, err := m.Exists(ctx, "root"); err != nil || !ok {
		t.Errorf("Exists(root) = (%v,%v), want (true,nil)", ok, err)
	}
	if ok, err := m.Exists(ctx, "pmnonexistent12345"); err != nil || ok {
		t.Error("non-existent user reported as existing")
	}
}

func TestModify_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("mod")
	defer cleanupUser(t, m, name)
	createTestUser(t, m, name)

	if err := m.Modify(ctx, name, user.ModifyOptions{Shell: "/bin/sh"}); err != nil {
		t.Fatalf("Modify: %v", err)
	}
	info, err := m.Get(ctx, name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if info.Shell != "/bin/sh" {
		t.Errorf("shell after modify = %s, want /bin/sh", info.Shell)
	}
}

func TestDelete_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("del")
	createTestUser(t, m, name)

	if err := m.Delete(ctx, name, user.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, err := m.Exists(ctx, name); err != nil || ok {
		t.Error("user still exists after delete")
	}
}

func TestDeleteWithHome_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("dlh")
	createTestUser(t, m, name)

	info, err := m.Get(ctx, name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	homeDir := info.HomeDir
	if err := m.Delete(ctx, name, user.DeleteOptions{RemoveHome: true}); err != nil {
		t.Fatalf("Delete with home: %v", err)
	}
	if ok, err := m.Exists(ctx, name); err != nil || ok {
		t.Error("user still exists after delete")
	}
	if _, err := os.Stat(homeDir); !os.IsNotExist(err) {
		t.Errorf("home directory was not removed, stat err = %v", err)
	}
}

func TestDeleteNonexistent_Integration(t *testing.T) {
	err := newManager(t).Delete(context.Background(), "pmnonexistent12345", user.DeleteOptions{})
	if err == nil {
		t.Fatal("expected error deleting a non-existent user")
	}
	// The typed error must carry userdel's exit code and stderr.
	var ce *exec.CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *exec.CommandError", err)
	}
	if ce.ExitCode == 0 {
		t.Errorf("CommandError.ExitCode = 0, want non-zero")
	}
	if ce.Stderr == "" {
		t.Errorf("CommandError.Stderr empty, want userdel's diagnostic")
	}
}

func TestLockUnlock_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("lck")
	defer cleanupUser(t, m, name)
	createTestUser(t, m, name)

	pw, _ := exec.NewSecret("TestPass123!")
	if err := m.SetPassword(ctx, name, pw); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if err := m.Lock(ctx, name); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if info, err := m.Get(ctx, name); err != nil || !info.Locked {
		t.Errorf("after Lock: Locked=%v err=%v, want locked", info.Locked, err)
	}
	if err := m.Unlock(ctx, name); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if info, err := m.Get(ctx, name); err != nil || info.Locked {
		t.Errorf("after Unlock: Locked=%v err=%v, want unlocked", info.Locked, err)
	}
}

func TestSetPassword_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("pwd")
	defer cleanupUser(t, m, name)
	createTestUser(t, m, name)

	pw, _ := exec.NewSecret("TestPass123!")
	if err := m.SetPassword(ctx, name, pw); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	info, err := m.Get(ctx, name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if info.Locked {
		t.Error("account locked after setting a password")
	}
}

func TestExpirePassword_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("exp")
	defer cleanupUser(t, m, name)
	createTestUser(t, m, name)

	pw, _ := exec.NewSecret("TestPass123!")
	if err := m.SetPassword(ctx, name, pw); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := m.ExpirePassword(ctx, name); err != nil {
		t.Fatalf("ExpirePassword: %v", err)
	}
}

func TestPrimaryGroup_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("pg")
	defer cleanupUser(t, m, name)
	createTestUser(t, m, name)

	group, err := m.PrimaryGroup(ctx, name)
	if err != nil {
		t.Fatalf("PrimaryGroup: %v", err)
	}
	if group == "" {
		t.Error("expected non-empty primary group")
	}
}

func TestSupplementaryGroups_Integration(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	name := testUsername("sg")
	groupName := testUsername("sgg")
	defer cleanupUser(t, m, name)
	defer func() { _ = m.GroupDelete(ctx, groupName) }()
	createTestUser(t, m, name)

	if err := m.GroupCreate(ctx, groupName, user.GroupCreateOptions{}); err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	if err := m.AddToGroup(ctx, name, groupName); err != nil {
		t.Fatalf("AddToGroup: %v", err)
	}

	groups, err := m.SupplementaryGroups(ctx, name)
	if err != nil {
		t.Fatalf("SupplementaryGroups: %v", err)
	}
	found := false
	for _, g := range groups {
		if g == groupName {
			found = true
		}
	}
	if !found {
		t.Errorf("group %q not in supplementary groups %v", groupName, groups)
	}
	primary, err := m.PrimaryGroup(ctx, name)
	if err != nil {
		t.Fatalf("PrimaryGroup: %v", err)
	}
	for _, g := range groups {
		if g == primary {
			t.Errorf("primary group %q must not appear in supplementary list", primary)
		}
	}
}
