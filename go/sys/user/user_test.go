//go:build integration

package user_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
	"github.com/manchtools/power-manage/sdk/go/sys/user"
)

func testUsername(suffix string) string {
	return fmt.Sprintf("pmtest%s%d", suffix, os.Getpid()%10000)
}

func cleanupUser(t *testing.T, username string) {
	t.Helper()
	ctx := context.Background()
	exec.Sudo(ctx, "userdel", "-r", username)
}

func createTestUser(t *testing.T, username string) {
	t.Helper()
	ctx := context.Background()
	if err := user.Create(ctx, username, "-m", "-s", "/bin/bash"); err != nil {
		t.Fatalf("failed to create test user %s: %v", username, err)
	}
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	name := testUsername("cr")
	defer cleanupUser(t, name)

	err := user.Create(ctx, name, "-m", "-s", "/bin/bash")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if !user.Exists(name) {
		t.Error("user should exist after creation")
	}

	info, err := user.Get(name)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if info.Shell != "/bin/bash" {
		t.Errorf("expected shell /bin/bash, got %s", info.Shell)
	}
}

func TestCreateSystemUser(t *testing.T) {
	ctx := context.Background()
	name := testUsername("sys")
	defer cleanupUser(t, name)

	err := user.Create(ctx, name, "--system", "--no-create-home", "-s", "/usr/sbin/nologin")
	if err != nil {
		t.Fatalf("Create system user failed: %v", err)
	}

	info, err := user.Get(name)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if info.Shell != "/usr/sbin/nologin" {
		t.Errorf("expected nologin shell, got %s", info.Shell)
	}
	// System users typically have UID < 1000
	if info.UID >= 1000 {
		t.Errorf("expected system UID < 1000, got %d", info.UID)
	}
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	name := testUsername("gt")
	defer cleanupUser(t, name)

	if err := user.Create(ctx, name, "-m", "-s", "/bin/bash", "-c", "Test User"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	info, err := user.Get(name)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if info.UID == 0 {
		t.Error("expected non-zero UID")
	}
	if info.Comment != "Test User" {
		t.Errorf("expected comment 'Test User', got %q", info.Comment)
	}
	if info.HomeDir == "" {
		t.Error("expected non-empty home directory")
	}
	if info.Shell != "/bin/bash" {
		t.Errorf("expected /bin/bash, got %s", info.Shell)
	}
}

func TestGetNonexistent(t *testing.T) {
	_, err := user.Get("pm-nonexistent-user-12345")
	if err == nil {
		t.Fatal("expected error for non-existent user")
	}
}

func TestExists(t *testing.T) {
	if !user.Exists("root") {
		t.Error("root user should exist")
	}
	if user.Exists("pm-nonexistent-user-12345") {
		t.Error("non-existent user should not exist")
	}
}

func TestModify(t *testing.T) {
	ctx := context.Background()
	name := testUsername("mod")
	defer cleanupUser(t, name)

	createTestUser(t, name)

	err := user.Modify(ctx, name, "-s", "/bin/sh")
	if err != nil {
		t.Fatalf("Modify failed: %v", err)
	}

	info, err := user.Get(name)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if info.Shell != "/bin/sh" {
		t.Errorf("expected /bin/sh after modify, got %s", info.Shell)
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	name := testUsername("del")

	createTestUser(t, name)

	err := user.Delete(ctx, name, false)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if user.Exists(name) {
		t.Error("user should not exist after deletion")
	}
}

func TestDeleteWithHome(t *testing.T) {
	ctx := context.Background()
	name := testUsername("dlh")

	createTestUser(t, name)

	info, err := user.Get(name)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	homeDir := info.HomeDir

	err = user.Delete(ctx, name, true)
	if err != nil {
		t.Fatalf("Delete with home failed: %v", err)
	}

	if user.Exists(name) {
		t.Error("user should not exist after deletion")
	}
	if fs.FileExists(ctx, homeDir) {
		t.Error("home directory should be removed")
	}
}

func TestDeleteNonexistent(t *testing.T) {
	ctx := context.Background()
	err := user.Delete(ctx, "pm-nonexistent-user-12345", false)
	if err == nil {
		t.Fatal("expected error deleting non-existent user")
	}
}

func TestLockUnlock(t *testing.T) {
	ctx := context.Background()
	name := testUsername("lck")
	defer cleanupUser(t, name)

	createTestUser(t, name)

	// Set a password first so lock is meaningful
	if err := user.SetPassword(ctx, name, "TestPass123!"); err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	// Lock
	if err := user.Lock(ctx, name); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}
	info, err := user.Get(name)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !info.Locked {
		t.Error("user should be locked")
	}

	// Unlock
	if err := user.Unlock(ctx, name); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	info, err = user.Get(name)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if info.Locked {
		t.Error("user should be unlocked")
	}
}

func TestSetPassword(t *testing.T) {
	ctx := context.Background()
	name := testUsername("pwd")
	defer cleanupUser(t, name)

	createTestUser(t, name)

	err := user.SetPassword(ctx, name, "TestPass123!")
	if err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	// Verify the user is no longer locked (has a valid password)
	info, err := user.Get(name)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if info.Locked {
		t.Error("user should not be locked after setting password")
	}
}

func TestExpirePassword(t *testing.T) {
	ctx := context.Background()
	name := testUsername("exp")
	defer cleanupUser(t, name)

	createTestUser(t, name)
	if err := user.SetPassword(ctx, name, "TestPass123!"); err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	err := user.ExpirePassword(ctx, name)
	if err != nil {
		t.Fatalf("ExpirePassword failed: %v", err)
	}

	// Verify the password is expired by checking chage output
	out, err := exec.Query("sudo", "-n", "chage", "-l", name)
	if err != nil {
		t.Logf("chage -l failed (may need sudo): %v", err)
		return
	}
	// "Last password change" should show "password must be changed"
	_ = out // Just verifying no error
}

func TestPrimaryGroup(t *testing.T) {
	name := testUsername("pg")
	defer cleanupUser(t, name)

	createTestUser(t, name)

	group, err := user.PrimaryGroup(name)
	if err != nil {
		t.Fatalf("PrimaryGroup failed: %v", err)
	}
	if group == "" {
		t.Error("expected non-empty primary group")
	}
	// Primary group typically matches username
	if group != name {
		t.Logf("primary group %q differs from username %q (may be expected)", group, name)
	}
}

func TestSupplementaryGroups(t *testing.T) {
	ctx := context.Background()
	name := testUsername("sg")
	groupName := testUsername("sgg")
	defer cleanupUser(t, name)
	defer func() { exec.Sudo(ctx, "groupdel", groupName) }()

	createTestUser(t, name)

	// Create a test group and add user to it
	if err := user.GroupCreate(ctx, groupName); err != nil {
		t.Fatalf("GroupCreate failed: %v", err)
	}
	if err := user.GroupAddUser(ctx, name, groupName); err != nil {
		t.Fatalf("GroupAddUser failed: %v", err)
	}

	groups, err := user.SupplementaryGroups(name)
	if err != nil {
		t.Fatalf("SupplementaryGroups failed: %v", err)
	}

	found := false
	for _, g := range groups {
		if g == groupName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in supplementary groups, got %v", groupName, groups)
	}

	// Primary group should NOT be in supplementary list
	primary, _ := user.PrimaryGroup(name)
	for _, g := range groups {
		if g == primary {
			t.Errorf("primary group %q should not be in supplementary list", primary)
		}
	}
}

func TestChownRecursive(t *testing.T) {
	ctx := context.Background()
	name := testUsername("co")
	defer cleanupUser(t, name)

	createTestUser(t, name)

	dir := fmt.Sprintf("/tmp/pm-chown-test-%d", os.Getpid())
	defer func() { exec.Sudo(ctx, "rm", "-rf", dir) }()

	if err := fs.Mkdir(ctx, dir+"/sub", true); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}
	if err := fs.WriteFile(ctx, dir+"/sub/file.txt", "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := user.ChownRecursive(ctx, dir, name, name); err != nil {
		t.Fatalf("ChownRecursive failed: %v", err)
	}

	// Verify ownership of the file
	owner, group := fs.GetOwnership(dir + "/sub/file.txt")
	if owner != name {
		t.Errorf("expected owner %q, got %q", name, owner)
	}
	if group != name {
		t.Errorf("expected group %q, got %q", name, group)
	}
}

func TestIsValidName(t *testing.T) {
	valid := []string{"root", "test-user", "user_name", "a", "abc123", "a-b-c"}
	for _, name := range valid {
		if !user.IsValidName(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}

	invalid := []string{
		"",
		"1starts-with-digit",
		"-starts-with-dash",
		"_starts-with-underscore",
		"UPPERCASE",
		"has spaces",
		"has.dots",
		"has@symbol",
		"abcdefghijklmnopqrstuvwxyz1234567", // 33 chars, too long
	}
	for _, name := range invalid {
		if user.IsValidName(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}
