package remote

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// fetchArchiveTo builds an Extract HTTP source over a fixture serving body with
// contentType, fetches into a fresh dest, and returns the error.
func fetchArchiveTo(t *testing.T, body []byte, contentType, urlPath string) error {
	t.Helper()
	fix := newArchiveFixture(t, body, contentType, urlPath, "")
	src, err := NewHTTP(HTTPConfig{URL: fix.srv.URL + fix.urlPath, Extract: true})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	_, ferr := src.Fetch(context.Background(), dest)
	return ferr
}

// TestArchive_CorruptBodies — a body that isn't a valid gzip/zip must surface a
// decode error, never a partially-populated dest.
func TestArchive_CorruptBodies(t *testing.T) {
	if err := fetchArchiveTo(t, []byte("this is not gzip"), "application/gzip", "/x.tar.gz"); err == nil {
		t.Error("corrupt gzip body returned nil error")
	}
	if err := fetchArchiveTo(t, []byte("this is not a zip"), "application/zip", "/x.zip"); err == nil {
		t.Error("corrupt zip body returned nil error")
	}
}

// TestArchive_FileDirConflict — a tar that declares a regular file "a" and then
// an entry "a/b" forces a real mkdir/create failure (the parent "a" is a file),
// exercising the extractor's mid-extract I/O error path. Belt-and-braces: a
// malformed archive must fail cleanly, not panic or half-write.
func TestArchive_FileDirConflict(t *testing.T) {
	body := buildTarGz(t, []archiveEntry{
		{name: "a", body: "i am a file"},
		{name: "a/b", body: "cannot live under a file"},
	})
	if err := fetchArchiveTo(t, body, "application/gzip", "/x.tar.gz"); err == nil {
		t.Error("tar with a file/dir path conflict returned nil error")
	}
}

// TestArchive_Non2xx — openArchiveBody must turn a non-2xx into an error.
func TestArchive_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	src, err := NewHTTP(HTTPConfig{URL: srv.URL + "/x.tar.gz", Extract: true})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if _, ferr := src.Fetch(context.Background(), filepath.Join(t.TempDir(), "out")); ferr == nil {
		t.Error("archive Fetch on a 502 returned nil error")
	}
}

// TestChownNoFollow_ErrorBranches walks every inode-type branch of chownNoFollow.
// Run as non-root, chown(0,0) fails with EPERM on each, which still executes the
// directory / regular-file / symlink / missing-target code paths (belt-and-
// braces: the privileged path must fail closed, not silently no-op).
func TestChownNoFollow_ErrorBranches(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chown(0,0) succeeds, so the error branches don't trigger")
	}
	dir := t.TempDir()

	regular := filepath.Join(dir, "file")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "d")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}

	for name, target := range map[string]string{
		"regular-file": regular,
		"directory":    subdir,
		"symlink":      link,
		"missing":      filepath.Join(dir, "nope"),
	} {
		if err := chownNoFollow(target, 0, 0); err == nil {
			t.Errorf("chownNoFollow(%s) = nil; want a permission/refusal error as non-root", name)
		}
	}
}

// TestApplyMode_OwnerPath — applyMode with an owner reaches ResolveOwnership +
// chownNoFollow; as non-root the chown fails, exercising the owner branch.
func TestApplyMode_OwnerPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chown succeeds")
	}
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyMode(f, "", "root", ""); err == nil {
		t.Error("applyMode(owner=root) as non-root returned nil; want an ownership error")
	}
}
