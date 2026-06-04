package remote

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestHTTPWipe_RemovesRecordedDest — Wipe on a path the test recorded
// (mimics post-Fetch state) succeeds and the path is gone afterwards.
// Same body fits every Source; tested through the HTTP impl because
// that's the one wired in so far.
func TestHTTPWipe_RemovesRecordedDest(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "tree")
	if err := os.MkdirAll(filepath.Join(dest, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "sub", "x"), []byte("y"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	recordDestUnder(t, dest)

	src, _ := NewHTTP(HTTPConfig{URL: "https://example.test/x"})
	if err := src.Wipe(context.Background(), dest); err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("dest still exists after Wipe; stat err = %v", err)
	}
}

// TestHTTPWipe_RefusesProtectedPaths — Wipe must refuse system paths
// even when called with a config that has nothing else wrong. The
// canWipe guard is the layer that catches this; the test exercises it
// end-to-end via Wipe so a future refactor can't silently bypass.
func TestHTTPWipe_RefusesProtectedPaths(t *testing.T) {
	src, _ := NewHTTP(HTTPConfig{URL: "https://example.test/x"})
	for _, p := range []string{"/etc", "/var/log", "/"} {
		t.Run("dest="+p, func(t *testing.T) {
			if err := src.Wipe(context.Background(), p); !errors.Is(err, ErrUnsafeDestination) {
				t.Fatalf("Wipe(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", p, err)
			}
		})
	}
}

// TestHTTPWipe_NoOpWhenDestMissing — wiping a path that was recorded
// but later deleted (or never created) should succeed quietly, not
// surface a confusing ENOENT to callers.
func TestHTTPWipe_NoOpWhenDestMissing(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "never-existed")
	recordDestUnder(t, dest)

	src, _ := NewHTTP(HTTPConfig{URL: "https://example.test/x"})
	if err := src.Wipe(context.Background(), dest); err != nil {
		t.Fatalf("Wipe on missing dest err = %v; want nil", err)
	}
}

// TestHTTPWipe_AllowsManagedRootsWithoutRecording — paths under the
// project-managed roots (/var/lib/power-manage/...) bypass the
// RecordDest requirement; that's the surface Wipe targets when an
// agent restarts after writing content in a prior session.
func TestHTTPWipe_AllowsManagedRootsWithoutRecording(t *testing.T) {
	// We can't actually rm the real /var/lib/power-manage/... in a
	// test, but canWipe's authorization decision should accept the
	// path so the call falls through to the rm step. We assert no
	// ErrUnsafeDestination — the only other expected outcome here is
	// nil (path doesn't exist → no-op) or an OS-level error if the
	// path happens to exist and isn't accessible. Either is fine; the
	// authorization layer is what we're locking in.
	src, _ := NewHTTP(HTTPConfig{URL: "https://example.test/x"})
	err := src.Wipe(context.Background(), "/var/lib/power-manage/test-wipe-allowance")
	if errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("Wipe under managed root returned ErrUnsafeDestination: %v", err)
	}
}
