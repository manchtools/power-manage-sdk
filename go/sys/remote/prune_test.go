package remote

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestPrune_RemovesFilesNotInKeep — the core mirror-with-delete
// behaviour. Files present locally but absent from the keep set are
// deleted; files in keep stay; empty directories left behind are
// cleaned up bottom-up.
func TestPrune_RemovesFilesNotInKeep(t *testing.T) {
	dest := t.TempDir()
	recordDestUnder(t, dest)
	mustWrite(t, filepath.Join(dest, "keep.txt"), "k")
	mustWrite(t, filepath.Join(dest, "drop.txt"), "d")
	mustWrite(t, filepath.Join(dest, "sub", "keep2.txt"), "k2")
	mustWrite(t, filepath.Join(dest, "sub", "drop2.txt"), "d2")

	keep := map[string]struct{}{
		"keep.txt":      {},
		"sub/keep2.txt": {},
	}
	if err := pruneTo(dest, keep); err != nil {
		t.Fatalf("pruneTo: %v", err)
	}
	mustExist(t, filepath.Join(dest, "keep.txt"))
	mustExist(t, filepath.Join(dest, "sub", "keep2.txt"))
	mustNotExist(t, filepath.Join(dest, "drop.txt"))
	mustNotExist(t, filepath.Join(dest, "sub", "drop2.txt"))
	// sub/ has a survivor so the dir stays.
	mustExist(t, filepath.Join(dest, "sub"))
}

// TestPrune_RemovesEmptiedDirectories — when a subdir's only files are
// pruned, the now-empty dir gets removed too. Keeps the tree clean
// after a multi-cycle drift.
func TestPrune_RemovesEmptiedDirectories(t *testing.T) {
	dest := t.TempDir()
	recordDestUnder(t, dest)
	mustWrite(t, filepath.Join(dest, "stale", "only.txt"), "x")
	keep := map[string]struct{}{} // nothing kept

	if err := pruneTo(dest, keep); err != nil {
		t.Fatalf("pruneTo: %v", err)
	}
	mustNotExist(t, filepath.Join(dest, "stale", "only.txt"))
	mustNotExist(t, filepath.Join(dest, "stale"))
	// The root dest stays — pruneTo doesn't delete the input dir.
	mustExist(t, dest)
}

// TestPrune_NoOpWhenAllFilesAreKept — when keep matches the tree
// exactly, pruneTo touches nothing.
func TestPrune_NoOpWhenAllFilesAreKept(t *testing.T) {
	dest := t.TempDir()
	recordDestUnder(t, dest)
	mustWrite(t, filepath.Join(dest, "a.txt"), "a")
	mustWrite(t, filepath.Join(dest, "sub", "b.txt"), "b")
	keep := map[string]struct{}{"a.txt": {}, "sub/b.txt": {}}
	if err := pruneTo(dest, keep); err != nil {
		t.Fatalf("pruneTo: %v", err)
	}
	mustExist(t, filepath.Join(dest, "a.txt"))
	mustExist(t, filepath.Join(dest, "sub", "b.txt"))
}

// TestPrune_MissingDestIsNotAnError — if dest doesn't exist (e.g. a
// first-time Fetch that hasn't extracted yet), pruneTo is a quiet
// no-op rather than ENOENT.
func TestPrune_MissingDestIsNotAnError(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "never")
	recordDestUnder(t, dest)
	if err := pruneTo(dest, nil); err != nil {
		t.Fatalf("pruneTo on missing dest: %v", err)
	}
}

// TestPrune_RefusesUnsafeDest — defense-in-depth. pruneTo must run the
// same path-safety guard as Wipe, so a bug elsewhere can't accidentally
// hand it /etc or "/".
func TestPrune_RefusesUnsafeDest(t *testing.T) {
	for _, p := range []string{"/", "/etc", ""} {
		t.Run("dest="+p, func(t *testing.T) {
			if err := pruneTo(p, nil); !errors.Is(err, ErrUnsafeDestination) {
				t.Fatalf("pruneTo(%q) = %v; want errors.Is(..., ErrUnsafeDestination)", p, err)
			}
		})
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}
func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to not exist; stat err = %v", path, err)
	}
}
