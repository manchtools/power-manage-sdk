//go:build integration

package fs_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

func tmpPath(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf("/tmp/pm-fs-test-%s-%d", name, os.Getpid())
}

func cleanup(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	fs.Remove(ctx, path)
}

func TestWriteFile(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "write")
	defer cleanup(t, path)

	err := fs.WriteFile(ctx, path, "hello world\n")
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Verify the file exists
	if !fs.FileExists(ctx, path) {
		t.Fatal("file should exist after WriteFile")
	}
}

func TestReadFile(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "read")
	defer cleanup(t, path)

	content := "hello world\n"
	err := fs.WriteFile(ctx, path, content)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	got, err := fs.ReadFile(ctx, path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if got != content {
		t.Errorf("expected %q, got %q", content, got)
	}
}

func TestReadFileNotFound(t *testing.T) {
	ctx := context.Background()
	got, err := fs.ReadFile(ctx, "/tmp/pm-nonexistent-file-12345")
	if err != nil {
		t.Fatalf("ReadFile should not error for missing file, got: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string for missing file, got %q", got)
	}
}

func TestReadFileBinary(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "binary")
	defer cleanup(t, path)

	// Write binary-ish content (no null bytes since tee/cat may not handle them)
	content := "line1\nline2\nline3\n"
	if err := fs.WriteFile(ctx, path, content); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	got, err := fs.ReadFile(ctx, path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if got != content {
		t.Errorf("expected %q, got %q", content, got)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "atomic")
	defer cleanup(t, path)

	content := "atomic content\n"
	err := fs.WriteFileAtomic(ctx, path, content, "0644", "root", "root")
	if err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	// Verify content
	got, err := fs.ReadFile(ctx, path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if got != content {
		t.Errorf("expected %q, got %q", content, got)
	}

	// Verify permissions
	out, err := exec.Query("stat", "-c", "%a", path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if strings.TrimSpace(out) != "644" {
		t.Errorf("expected mode 644, got %s", strings.TrimSpace(out))
	}

	// Verify ownership
	owner, group := fs.GetOwnership(path)
	if owner != "root" {
		t.Errorf("expected owner 'root', got %q", owner)
	}
	if group != "root" {
		t.Errorf("expected group 'root', got %q", group)
	}
}

func TestWriteFileAtomicCleansUpOnError(t *testing.T) {
	ctx := context.Background()
	// Use a directory that doesn't exist as parent for the temp file
	path := "/tmp/pm-nonexistent-dir-12345/file.txt"
	tmpFile := path + ".pm-tmp"

	_ = fs.WriteFileAtomic(ctx, path, "content", "0644", "root", "root")
	// The temp file should not be left behind
	if fs.FileExists(ctx, tmpFile) {
		t.Error("temp file should be cleaned up after error")
		fs.Remove(ctx, tmpFile)
	}
}

func TestFileExists(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "exists")
	defer cleanup(t, path)

	// Should not exist yet
	if fs.FileExists(ctx, path) {
		t.Error("file should not exist yet")
	}

	// Create it
	if err := fs.WriteFile(ctx, path, "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Should exist now
	if !fs.FileExists(ctx, path) {
		t.Error("file should exist after creation")
	}
}

func TestFileExistsRestrictedDir(t *testing.T) {
	ctx := context.Background()
	// /etc/sudoers.d is typically mode 0750, not readable by normal users
	// but our FileExists uses sudo, so it should work
	exists := fs.FileExists(ctx, "/etc/sudoers.d")
	if !exists {
		t.Error("expected /etc/sudoers.d to exist (via sudo)")
	}
}

func TestSetMode(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "mode")
	defer cleanup(t, path)

	if err := fs.WriteFile(ctx, path, "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := fs.SetMode(ctx, path, "0755"); err != nil {
		t.Fatalf("SetMode failed: %v", err)
	}

	out, err := exec.Query("stat", "-c", "%a", path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if strings.TrimSpace(out) != "755" {
		t.Errorf("expected mode 755, got %s", strings.TrimSpace(out))
	}
}

func TestSetModeEmpty(t *testing.T) {
	ctx := context.Background()
	// Empty mode should be a no-op
	err := fs.SetMode(ctx, "/tmp/nonexistent", "")
	if err != nil {
		t.Errorf("SetMode with empty mode should be no-op, got: %v", err)
	}
}

func TestSetOwnership(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "ownership")
	defer cleanup(t, path)

	if err := fs.WriteFile(ctx, path, "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := fs.SetOwnership(ctx, path, "root", "root"); err != nil {
		t.Fatalf("SetOwnership failed: %v", err)
	}

	owner, group := fs.GetOwnership(path)
	if owner != "root" {
		t.Errorf("expected owner 'root', got %q", owner)
	}
	if group != "root" {
		t.Errorf("expected group 'root', got %q", group)
	}
}

func TestSetPermissions(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "perms")
	defer cleanup(t, path)

	if err := fs.WriteFile(ctx, path, "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := fs.SetPermissions(ctx, path, "0600", "root", "root"); err != nil {
		t.Fatalf("SetPermissions failed: %v", err)
	}

	out, err := exec.Query("stat", "-c", "%a", path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if strings.TrimSpace(out) != "600" {
		t.Errorf("expected mode 600, got %s", strings.TrimSpace(out))
	}

	owner, group := fs.GetOwnership(path)
	if owner != "root" || group != "root" {
		t.Errorf("expected root:root, got %s:%s", owner, group)
	}
}

func TestRemove(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "remove")

	if err := fs.WriteFile(ctx, path, "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	fs.Remove(ctx, path)

	if fs.FileExists(ctx, path) {
		t.Error("file should be removed")
	}

	// Removing a non-existent file should not panic
	fs.Remove(ctx, path)
}

func TestRemoveStrict(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "removestrict")

	if err := fs.WriteFile(ctx, path, "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err := fs.RemoveStrict(ctx, path)
	if err != nil {
		t.Fatalf("RemoveStrict failed: %v", err)
	}

	if fs.FileExists(ctx, path) {
		t.Error("file should be removed")
	}
}

func TestCopyFile(t *testing.T) {
	ctx := context.Background()
	src := tmpPath(t, "copysrc")
	dst := tmpPath(t, "copydst")
	defer cleanup(t, src)
	defer cleanup(t, dst)

	content := "copy me\n"
	if err := fs.WriteFile(ctx, src, content); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := fs.CopyFile(ctx, src, dst); err != nil {
		t.Fatalf("CopyFile failed: %v", err)
	}

	got, err := fs.ReadFile(ctx, dst)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if got != content {
		t.Errorf("expected %q, got %q", content, got)
	}
}

func TestCopyFileWithPermissions(t *testing.T) {
	ctx := context.Background()
	src := tmpPath(t, "copyperm-src")
	dst := tmpPath(t, "copyperm-dst")
	defer cleanup(t, src)
	defer cleanup(t, dst)

	if err := fs.WriteFile(ctx, src, "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := fs.CopyFileWithPermissions(ctx, src, dst, "0600", "root", "root"); err != nil {
		t.Fatalf("CopyFileWithPermissions failed: %v", err)
	}

	out, err := exec.Query("stat", "-c", "%a", dst)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if strings.TrimSpace(out) != "600" {
		t.Errorf("expected mode 600, got %s", strings.TrimSpace(out))
	}
}

func TestMkdir(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "mkdir")
	defer func() { exec.Sudo(ctx, "rm", "-rf", path) }()

	if err := fs.Mkdir(ctx, path, false); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}

	if !fs.FileExists(ctx, path) {
		t.Error("directory should exist")
	}
}

func TestMkdirRecursive(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "mkdir-recursive") + "/a/b/c"
	basePath := tmpPath(t, "mkdir-recursive")
	defer func() { exec.Sudo(ctx, "rm", "-rf", basePath) }()

	if err := fs.Mkdir(ctx, path, true); err != nil {
		t.Fatalf("Mkdir recursive failed: %v", err)
	}

	if !fs.FileExists(ctx, path) {
		t.Error("nested directory should exist")
	}
}

func TestMkdirWithPermissions(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "mkdir-perms")
	defer func() { exec.Sudo(ctx, "rm", "-rf", path) }()

	if err := fs.MkdirWithPermissions(ctx, path, "0750", "root", "root", false); err != nil {
		t.Fatalf("MkdirWithPermissions failed: %v", err)
	}

	out, err := exec.Query("stat", "-c", "%a", path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if strings.TrimSpace(out) != "750" {
		t.Errorf("expected mode 750, got %s", strings.TrimSpace(out))
	}
}

func TestRemoveDir(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "rmdir")

	if err := fs.Mkdir(ctx, path+"/sub", true); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}
	if err := fs.WriteFile(ctx, path+"/sub/file.txt", "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := fs.RemoveDir(ctx, path); err != nil {
		t.Fatalf("RemoveDir failed: %v", err)
	}

	if fs.FileExists(ctx, path) {
		t.Error("directory should be removed")
	}
}

func TestOwnership(t *testing.T) {
	tests := []struct {
		owner, group, expected string
	}{
		{"root", "root", "root:root"},
		{"root", "", "root"},
		{"", "root", ":root"},
		{"", "", ""},
		{"user", "group", "user:group"},
	}
	for _, tt := range tests {
		got := fs.Ownership(tt.owner, tt.group)
		if got != tt.expected {
			t.Errorf("Ownership(%q, %q) = %q, want %q", tt.owner, tt.group, got, tt.expected)
		}
	}
}

func TestGetOwnership(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "getowner")
	defer cleanup(t, path)

	if err := fs.WriteFile(ctx, path, "test"); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := fs.SetOwnership(ctx, path, "root", "root"); err != nil {
		t.Fatalf("SetOwnership failed: %v", err)
	}

	owner, group := fs.GetOwnership(path)
	if owner != "root" {
		t.Errorf("expected owner 'root', got %q", owner)
	}
	if group != "root" {
		t.Errorf("expected group 'root', got %q", group)
	}
}

func TestGetOwnershipMissing(t *testing.T) {
	owner, group := fs.GetOwnership("/tmp/pm-nonexistent-12345")
	if owner != "" || group != "" {
		t.Errorf("expected empty for missing file, got %q:%q", owner, group)
	}
}

func TestContentRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := tmpPath(t, "roundtrip")
	defer cleanup(t, path)

	// This is the regression test for the idempotency bug:
	// content with trailing newline should round-trip exactly.
	content := "# SSH Config\nPort 22\nPermitRootLogin no\n"

	err := fs.WriteFileAtomic(ctx, path, content, "0644", "root", "root")
	if err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	got, err := fs.ReadFile(ctx, path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if got != content {
		t.Errorf("content mismatch:\n  expected: %q\n  got:      %q", content, got)
	}
}
