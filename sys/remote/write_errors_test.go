package remote

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A read-only destination directory forces the create/mkdir/rename failure
// branches of the streaming writers without instrumenting production code — the
// "belt and braces" failure modes: a write that can't land must surface an
// error, never silently succeed or leave a partial file. Skipped as root (which
// bypasses the permission bits).

func TestHTTPFetch_WriteIntoReadOnlyDir_Errors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	ro := t.TempDir()
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })

	fix := newHTTPFixture(t, []byte("payload"), "etag-1")
	src, err := NewHTTP(HTTPConfig{URL: fix.srv.URL})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	// dest under a subdir that can't be created (parent is read-only).
	if _, ferr := src.Fetch(context.Background(), filepath.Join(ro, "sub", "out")); ferr == nil {
		t.Error("Fetch into a read-only dir returned nil error")
	}
}

func TestS3Fetch_WriteIntoReadOnlyDir_Errors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	ro := t.TempDir()
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })

	fix := newS3Fixture(t, "bucket", "key", []byte("payload"), "etag-1")
	src, err := NewS3(S3Config{Endpoint: fix.srv.URL, Bucket: "bucket", Key: "key"})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	if _, ferr := src.Fetch(context.Background(), filepath.Join(ro, "sub", "out")); ferr == nil {
		t.Error("S3 Fetch into a read-only dir returned nil error")
	}
}

// TestRestoreUntracked_WriteError — restoring an untracked snapshot into a
// read-only tree must fail (the file would otherwise be silently lost on a
// checkout).
func TestRestoreUntracked_WriteError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	ro := t.TempDir()
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })

	snap := []untrackedFile{{relPath: "sub/u", body: []byte("x"), mode: 0o600}}
	if err := restoreUntracked(ro, snap); err == nil {
		t.Error("restoreUntracked into a read-only dir returned nil error")
	}
}
