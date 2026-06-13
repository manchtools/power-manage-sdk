package remote

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A tar header can under-report an entry's size (hdr.Size is attacker
// controlled). The pre-extract cumulative check trusts that number, so the
// actual copy must be bounded independently — otherwise one lying entry
// streams unbounded bytes to disk before the post-write total is checked.
// This mirrors the zip branch, which already bounds with a LimitReader.
func TestWriteTarEntry_BoundsCopyToRemainingBudget(t *testing.T) {
	out := filepath.Join(t.TempDir(), "f")
	body := bytes.Repeat([]byte("A"), 4096) // far larger than the limit
	n, err := writeArchiveEntry(out, bytes.NewReader(body), 0o644, 16)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("writeArchiveEntry over-limit err = %v, want ErrIntegrity", err)
	}
	// The copy must stop at limit+1 (the over-read sentinel), never drain
	// the whole oversized body to disk.
	if n > 17 {
		t.Errorf("wrote %d bytes, want <= limit+1 (17); copy was not bounded", n)
	}
	if info, statErr := os.Stat(out); statErr == nil && info.Size() > 17 {
		t.Errorf("on-disk file is %d bytes, want <= 17", info.Size())
	}
}

func TestWriteTarEntry_WithinBudgetSucceeds(t *testing.T) {
	out := filepath.Join(t.TempDir(), "f")
	n, err := writeArchiveEntry(out, bytes.NewReader([]byte("hello")), 0o644, 1024)
	if err != nil {
		t.Fatalf("writeArchiveEntry within budget err = %v, want nil", err)
	}
	if n != 5 {
		t.Errorf("wrote %d bytes, want 5", n)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "hello" {
		t.Errorf("file content = %q, want %q", got, "hello")
	}
}
