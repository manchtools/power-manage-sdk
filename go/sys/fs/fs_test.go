//go:build integration

package fs_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// missingPath returns a path guaranteed not to exist — a child of a fresh, empty
// t.TempDir — so the missing-file tests can't flake on a reused/shared host that
// happens to have a fixed /tmp literal lying around.
func missingPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "definitely-missing")
}

// intManager builds a real Manager for the integration job: Direct when the job
// runs as root, otherwise Sudo (the CI default). The Direct backend exercises
// the fd-safe path; Sudo exercises the escalated tee/mv path.
func intManager(t *testing.T) fs.Manager {
	t.Helper()
	b := exec.Sudo
	if os.Geteuid() == 0 {
		b = exec.Direct
	}
	r, err := exec.NewRunner(b)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	m, err := fs.New(r)
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	return m
}

func tmpPath(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf("/tmp/pm-fs-test-%s-%d", name, os.Getpid())
}

func cleanup(t *testing.T, m fs.Manager, path string) {
	t.Helper()
	_ = m.Remove(context.Background(), path)
}

// statMode returns the permission bits of path via os.Stat (metadata is
// world-readable even when the file is root-owned).
func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func TestWriteAndReadRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := intManager(t)
	path := tmpPath(t, "write")
	defer cleanup(t, m, path)

	content := []byte("hello world\n")
	if err := m.WriteFile(ctx, path, content, fs.WriteOptions{}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if ok, err := m.Exists(ctx, path); err != nil || !ok {
		t.Fatalf("Exists = (%v,%v), want (true,nil)", ok, err)
	}
	got, err := m.ReadFile(ctx, path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("ReadFile = %q, want %q", got, content)
	}
}

func TestReadFileNotFound(t *testing.T) {
	got, err := intManager(t).ReadFile(context.Background(), missingPath(t))
	if err != nil {
		t.Fatalf("ReadFile(missing) should not error, got: %v", err)
	}
	if got != nil {
		t.Errorf("ReadFile(missing) = %q, want nil", got)
	}
}

func TestWriteFileWithModeAndOwnership(t *testing.T) {
	ctx := context.Background()
	m := intManager(t)
	path := tmpPath(t, "atomic")
	defer cleanup(t, m, path)

	content := []byte("# SSH Config\nPort 22\nPermitRootLogin no\n")
	if err := m.WriteFile(ctx, path, content, fs.WriteOptions{Mode: 0o644, Owner: "root", Group: "root"}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := m.ReadFile(ctx, path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch:\n  expected: %q\n  got:      %q", content, got)
	}
	if mode := statMode(t, path); mode != 0o644 {
		t.Errorf("mode = %v, want 0644", mode)
	}
	if owner, group := fs.GetOwnership(path); owner != "root" || group != "root" {
		t.Errorf("ownership = %s:%s, want root:root", owner, group)
	}
}

func TestSetModeAndOwnership(t *testing.T) {
	ctx := context.Background()
	m := intManager(t)
	path := tmpPath(t, "perms")
	defer cleanup(t, m, path)

	if err := m.WriteFile(ctx, path, []byte("x"), fs.WriteOptions{}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := m.SetMode(ctx, path, 0o600); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	if mode := statMode(t, path); mode != 0o600 {
		t.Errorf("mode = %v, want 0600", mode)
	}
	if err := m.SetOwnership(ctx, path, "root", "root"); err != nil {
		t.Fatalf("SetOwnership: %v", err)
	}
	if owner, group := fs.GetOwnership(path); owner != "root" || group != "root" {
		t.Errorf("ownership = %s:%s, want root:root", owner, group)
	}
}

func TestExistsRestrictedDir(t *testing.T) {
	// Exists probes through the privilege backend, so it should resolve a
	// root-only path even though the test user can't read it. Pick the first
	// restricted path that exists on this host image rather than assume a
	// distro-specific one, and skip if none is present.
	var path string
	for _, c := range []string{"/etc/sudoers.d", "/etc/ssl/private", "/root"} {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("no restricted path available on this host image")
	}
	ok, err := intManager(t).Exists(context.Background(), path)
	if err != nil {
		t.Fatalf("Exists(%s): %v", path, err)
	}
	if !ok {
		t.Errorf("expected %s to exist (via the privilege backend)", path)
	}
}

func TestRemove(t *testing.T) {
	ctx := context.Background()
	m := intManager(t)
	path := tmpPath(t, "remove")

	if err := m.WriteFile(ctx, path, []byte("x"), fs.WriteOptions{}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := m.Remove(ctx, path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if ok, _ := m.Exists(ctx, path); ok {
		t.Error("file should be removed")
	}
	// rm -f is idempotent: removing an absent file succeeds.
	if err := m.Remove(ctx, path); err != nil {
		t.Errorf("Remove of an absent file = %v, want nil (rm -f)", err)
	}
}

func TestCopy(t *testing.T) {
	ctx := context.Background()
	m := intManager(t)
	src := tmpPath(t, "copysrc")
	dst := tmpPath(t, "copydst")
	defer cleanup(t, m, src)
	defer cleanup(t, m, dst)

	content := []byte("copy me\n")
	if err := m.WriteFile(ctx, src, content, fs.WriteOptions{}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := m.Copy(ctx, src, dst, fs.WriteOptions{Mode: 0o600}); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	got, err := m.ReadFile(ctx, dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("copied content = %q, want %q", got, content)
	}
	if mode := statMode(t, dst); mode != 0o600 {
		t.Errorf("dst mode = %v, want 0600", mode)
	}
}

func TestMkdirAndRemoveDir(t *testing.T) {
	ctx := context.Background()
	m := intManager(t)
	base := tmpPath(t, "mkdir")
	defer func() { _ = m.RemoveDir(ctx, base) }()

	leaf := base + "/a/b"
	if err := m.Mkdir(ctx, leaf, fs.MkdirOptions{Mode: 0o750, Owner: "root", Group: "root", Recursive: true}); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if ok, _ := m.Exists(ctx, leaf); !ok {
		t.Fatal("nested directory should exist")
	}
	// Mode applies to the target (leaf) directory; mkdir -p leaves parents at
	// their default mode.
	if mode := statMode(t, leaf); mode != 0o750 {
		t.Errorf("leaf dir mode = %v, want 0750", mode)
	}
	if err := m.WriteFile(ctx, base+"/a/b/file.txt", []byte("x"), fs.WriteOptions{}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := m.RemoveDir(ctx, base); err != nil {
		t.Fatalf("RemoveDir: %v", err)
	}
	if ok, _ := m.Exists(ctx, base); ok {
		t.Error("directory should be removed")
	}
}

func TestOwnershipHelper(t *testing.T) {
	for _, tt := range []struct{ owner, group, want string }{
		{"root", "root", "root:root"},
		{"root", "", "root"},
		{"", "root", ":root"},
		{"", "", ""},
		{"user", "group", "user:group"},
	} {
		if got := fs.Ownership(tt.owner, tt.group); got != tt.want {
			t.Errorf("Ownership(%q,%q) = %q, want %q", tt.owner, tt.group, got, tt.want)
		}
	}
}

func TestGetOwnershipMissing(t *testing.T) {
	if owner, group := fs.GetOwnership(missingPath(t)); owner != "" || group != "" {
		t.Errorf("GetOwnership(missing) = %q:%q, want empties", owner, group)
	}
}
