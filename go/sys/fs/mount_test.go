package fs

import (
	"os/exec"
	"testing"
)

func TestIsReadOnly(t *testing.T) {
	// Skip if findmnt is not available.
	if _, err := exec.LookPath("findmnt"); err != nil {
		t.Skip("findmnt not available")
	}

	// The root filesystem should generally be mounted read-write.
	ro, err := IsReadOnly("/")
	if err != nil {
		t.Fatalf("IsReadOnly(/): %v", err)
	}
	if ro {
		t.Log("root filesystem is read-only (unusual but valid on immutable systems)")
	}

	// /proc should be readable (it may show as special filesystem).
	// Just verify no panic or unexpected error.
	_, _ = IsReadOnly("/proc")
}

func TestRemountRW(t *testing.T) {
	// RemountRW requires sudo and a real mount point. Skip in unit tests.
	t.Skip("RemountRW requires root privileges")
}
