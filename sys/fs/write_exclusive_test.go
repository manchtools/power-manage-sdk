package fs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// These run against a real temp directory through the Direct backend (see
// directManager in manager_test.go): the whole value of an exclusive create is
// what the kernel actually does, so a fake would prove nothing.

// TestWriteFileExclusive_CreatesThenRefuses pins the primitive the firewalld
// backend's create-only cleanup rests on: the FIRST call creates and the SECOND
// reports ErrExists without touching the content. If the second call silently
// overwrote, a caller would conclude it owned a file it did not create and could
// go on to delete someone else's definition.
func TestWriteFileExclusive_CreatesThenRefuses(t *testing.T) {
	m := directManager(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "svc.xml")

	if err := m.WriteFileExclusive(ctx, path, []byte("mine"), WriteOptions{Mode: 0o644}); err != nil {
		t.Fatalf("first WriteFileExclusive: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "mine" {
		t.Fatalf("after create: content = %q, err = %v; want %q", got, err, "mine")
	}

	err = m.WriteFileExclusive(ctx, path, []byte("theirs"), WriteOptions{Mode: 0o644})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second WriteFileExclusive err = %v, want ErrExists (errors.Is-matchable)", err)
	}
	// The refusal must be total: no partial write, no truncation.
	got, err = os.ReadFile(path)
	if err != nil || string(got) != "mine" {
		t.Errorf("a refused exclusive write modified the file: content = %q, err = %v; want %q untouched", got, err, "mine")
	}
}

// A file planted by someone else — including one that appears between a caller's
// would-be probe and its write — must produce ErrExists just the same. This is
// the race the firewalld backend used to have with Exists-then-WriteFile.
func TestWriteFileExclusive_RefusesForeignFile(t *testing.T) {
	m := directManager(t)
	path := filepath.Join(t.TempDir(), "svc.xml")
	if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := m.WriteFileExclusive(context.Background(), path, []byte("ours"), WriteOptions{Mode: 0o644})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v, want ErrExists for a pre-existing foreign file", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "foreign" {
		t.Errorf("foreign content was clobbered: %q", got)
	}
}

// Backup is meaningless for a call that never replaces content, so it is
// rejected rather than silently ignored.
func TestWriteFileExclusive_RejectsBackup(t *testing.T) {
	m := directManager(t)
	dir := t.TempDir()
	err := m.WriteFileExclusive(context.Background(), filepath.Join(dir, "a.xml"), []byte("x"),
		WriteOptions{Mode: 0o644, Backup: filepath.Join(dir, "a.bak")})
	if !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("err = %v, want ErrInvalidPath for a Backup on an exclusive write", err)
	}
}
