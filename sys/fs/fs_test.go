//go:build integration

package fs_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// foreignLocale returns an installed non-English UTF-8 locale (Japanese or
// Chinese), or "" if none is present. Used to exercise the locale guard.
func foreignLocale(t *testing.T) string {
	t.Helper()
	out, err := osexec.Command("locale", "-a").Output()
	if err != nil {
		return ""
	}
	installed := strings.Split(string(out), "\n")
	for canonical, variants := range map[string][]string{
		"ja_JP.UTF-8": {"ja_JP.utf8", "ja_JP.UTF-8"},
		"zh_CN.UTF-8": {"zh_CN.utf8", "zh_CN.UTF-8"},
	} {
		for _, v := range variants {
			for _, have := range installed {
				if strings.EqualFold(strings.TrimSpace(have), v) {
					return canonical
				}
			}
		}
	}
	return ""
}

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
	// Explicit-absence contract: a missing file is a wrapped os.ErrNotExist, NOT a
	// silent (nil,nil) — so a caller can tell "absent" from "present but empty".
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadFile(missing) err = %v, want errors.Is(..., os.ErrNotExist)", err)
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

// TestWriteFile_ReplacesSymlinkTargetNotFollowed is the real-system proof of the
// symlink-safety fix: when the target path is a pre-planted symlink, the write
// must REPLACE the symlink with a regular file (rename, via mv -T on the
// escalated path / O_NOFOLLOW rename on the Direct path) and must NOT follow it
// to clobber the symlink's destination. /tmp is sticky+root-owned, so the
// escalated path's parent check admits it.
func TestWriteFile_ReplacesSymlinkTargetNotFollowed(t *testing.T) {
	ctx := context.Background()
	m := intManager(t)

	sentinel := tmpPath(t, "sym-sentinel")
	link := tmpPath(t, "sym-link")
	defer cleanup(t, m, sentinel)
	defer cleanup(t, m, link)

	if err := m.WriteFile(ctx, sentinel, []byte("SENTINEL\n"), fs.WriteOptions{}); err != nil {
		t.Fatalf("seed sentinel: %v", err)
	}
	_ = os.Remove(link)
	if err := os.Symlink(sentinel, link); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	if err := m.WriteFile(ctx, link, []byte("newcontent\n"), fs.WriteOptions{}); err != nil {
		t.Fatalf("WriteFile(symlinked target): %v", err)
	}

	// The symlink's destination must be untouched (the write did not follow it).
	if got, _ := m.ReadFile(ctx, sentinel); string(got) != "SENTINEL\n" {
		t.Errorf("sentinel was clobbered through the symlink: %q", got)
	}
	// The target path is now a regular file holding the new content.
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("target is still a symlink (err=%v, mode=%v); the symlink was followed, not replaced", err, fi.Mode())
	}
	if got, _ := m.ReadFile(ctx, link); string(got) != "newcontent\n" {
		t.Errorf("target content = %q, want the new content", got)
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

func TestCopyTree(t *testing.T) {
	ctx := context.Background()
	m := intManager(t)
	src := tmpPath(t, "treesrc")
	dst := tmpPath(t, "treedst")
	defer func() { _ = m.RemoveDir(ctx, src); _ = m.RemoveDir(ctx, dst) }()

	// A src tree with a regular file, a DOTFILE (proves -a copies hidden files),
	// and a nested subdir (proves recursion). Setup via os.* (the test user owns
	// /tmp); the subject under test is the privileged CopyTree.
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		filepath.Join(src, ".bashrc"):      "export X=1\n",
		filepath.Join(src, "sub", "f.txt"): "nested\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// dst does not exist yet: -T makes dst a copy of src's CONTENTS (the merge
	// semantics), never dst/treesrc.
	if err := m.CopyTree(ctx, src, dst, fs.WriteOptions{}); err != nil {
		t.Fatalf("CopyTree: %v", err)
	}
	for _, rel := range []string{".bashrc", "sub/f.txt"} {
		if ok, err := m.Exists(ctx, filepath.Join(dst, rel)); err != nil || !ok {
			t.Errorf("dst is missing %q after CopyTree (Exists=%v, err=%v)", rel, ok, err)
		}
	}
	if ok, _ := m.Exists(ctx, filepath.Join(dst, filepath.Base(src))); ok {
		t.Error("CopyTree nested the source under dst (dst/<src> exists) — -T should merge into dst")
	}

	// Idempotent re-run into the now-existing dst must not error (merge).
	if err := m.CopyTree(ctx, src, dst, fs.WriteOptions{Mode: 0o700}); err != nil {
		t.Fatalf("CopyTree (re-run/merge): %v", err)
	}
	if mode := statMode(t, dst); mode != 0o700 {
		t.Errorf("dst root mode = %v, want 0700 (Mode applies to the root)", mode)
	}
}

func TestWriteReader_StreamsAndIsAtomic(t *testing.T) {
	ctx := context.Background()
	m := intManager(t)
	path := tmpPath(t, "stream")
	defer cleanup(t, m, path)

	// A payload well past one io.Copy buffer, to exercise chunked streaming. It
	// is intentionally newline-free and multi-megabyte — exactly the binary
	// artifact WriteReader exists for. Verification reads the file back with a
	// direct os.ReadFile (the file is written world-readable below), NOT
	// m.ReadFile: the escalated ReadFile streams `cat` through the line-buffered
	// Runner (1 MiB cap, output-oriented) and cannot faithfully return a large
	// no-newline blob — a limitation of ReadFile, not of WriteReader.
	payload := strings.Repeat("0123456789abcdef", 200000) // ~3 MB
	if err := m.WriteReader(ctx, path, strings.NewReader(payload), fs.WriteOptions{Mode: 0o644}); err != nil {
		t.Fatalf("WriteReader: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != payload {
		t.Errorf("streamed content mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	if mode := statMode(t, path); mode != 0o644 {
		t.Errorf("mode = %v, want 0644", mode)
	}

	// Reader-error atomicity is guaranteed only on the Direct (root, fd-anchored)
	// backend — io.Copy aborts before the rename. The escalated path pipes to a
	// root shell that renames on stdin-EOF, so it intentionally does NOT promise
	// non-clobber on a truncated reader (see WriteReader's doc); skip there.
	if os.Geteuid() != 0 {
		t.Skip("reader-error atomicity is a Direct-backend guarantee; run as root to exercise it")
	}
	if err := m.WriteReader(ctx, path, &failingReader{failAfter: 1024}, fs.WriteOptions{Mode: 0o644}); err == nil {
		t.Fatal("WriteReader with a mid-stream failing reader should error")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back after failed stream: %v", err)
	}
	if string(after) != payload {
		t.Errorf("a failed stream clobbered the existing file: got %d bytes, want the original %d", len(after), len(payload))
	}
}

// failingReader yields failAfter bytes then errors, to drive WriteReader's
// mid-stream failure path.
type failingReader struct {
	failAfter int
	n         int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n >= r.failAfter {
		return 0, errors.New("simulated mid-stream read failure")
	}
	p[0] = 'x'
	r.n++
	return 1, nil
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

// TestReadFile_MissingUnderForeignLocale is the end-to-end locale guard: under a
// non-English process locale, ReadFile of a missing file must still return
// (nil,nil). It fails if the Runner stops forcing LC_ALL=C — cat's translated
// "No such file" message would then be misread as a hard error. (The whole
// integration suite also runs under ja_JP via the harness; this is the explicit,
// self-contained pin that holds even when run under C.)
func TestReadFile_MissingUnderForeignLocale(t *testing.T) {
	loc := foreignLocale(t)
	if loc == "" {
		t.Skip("no ja/zh locale installed to exercise the locale guard")
	}
	t.Setenv("LANG", loc)
	t.Setenv("LC_ALL", loc)
	got, err := intManager(t).ReadFile(context.Background(), missingPath(t))
	// The escalated cat path classifies absence by matching "No such file" in
	// stderr; that match only holds because the Runner forces LC_ALL=C. Under a
	// foreign LANG/LC_ALL it must STILL resolve to os.ErrNotExist (not a cmdError).
	if !errors.Is(err, os.ErrNotExist) || got != nil {
		t.Fatalf("ReadFile(missing) under %s = (%q,%v), want (nil, ErrNotExist) — the Runner must force LC_ALL=C", loc, got, err)
	}
}
