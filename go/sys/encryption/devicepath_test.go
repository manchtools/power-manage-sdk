package encryption

import (
	"context"
	"errors"
	"testing"
)

// Threat model: devicePath reaches cryptsetup / systemd-cryptenroll argv,
// which run as ROOT. A flag-shaped value ("--header=...", "--key-file",
// "--master-key-file") would be parsed by cryptsetup as an option,
// redirecting the privileged operation; a path-escape ("/dev/../etc/x")
// would point it elsewhere. validateDevicePath must require an absolute,
// canonical path under /dev/, which makes both impossible (a "/dev/"-
// prefixed value can't begin with '-', and a canonical path has no `..`).

func TestValidateDevicePath_RejectsUnsafe(t *testing.T) {
	// Wrong cases derived from the threat model, not from the validator.
	bad := []string{
		"",                   // empty
		"--header=/tmp/evil", // flag injection
		"-d",                 // flag injection
		"/etc/passwd",        // outside /dev
		"sda3",               // relative
		"dev/sda3",           // relative
		"/dev/../etc/shadow", // path escape
		"/dev/./sda3",        // non-canonical
		"/dev//sda3",         // non-canonical (redundant sep)
		"/dev/",              // names the directory, no device
		"/dev",               // the directory itself
		"/dev/sda3\n",        // trailing newline (arg smuggling / log forging)
		"/dev/sda3\x00extra", // NUL
		"/dev/disk\rby-uuid", // CR
	}
	for _, d := range bad {
		if err := validateDevicePath(d); err == nil {
			t.Errorf("validateDevicePath(%q) = nil, want ErrInvalidDevicePath", d)
		} else if !errors.Is(err, ErrInvalidDevicePath) {
			t.Errorf("validateDevicePath(%q) error = %v, want ErrInvalidDevicePath", d, err)
		}
	}
}

func TestValidateDevicePath_AcceptsRealDevices(t *testing.T) {
	// Must not over-reject the real shapes the agent passes: plain block
	// devices, NVMe partitions, device-mapper names, and by-uuid / by-label
	// symlink paths (all live under /dev/).
	for _, d := range []string{
		"/dev/sda3",
		"/dev/nvme0n1p3",
		"/dev/mapper/cryptroot",
		"/dev/disk/by-uuid/4c1f-9a2b-deadbeef",
		"/dev/null",
	} {
		if err := validateDevicePath(d); err != nil {
			t.Errorf("validateDevicePath(%q) = %v, want nil", d, err)
		}
	}
}

// Each exported LUKS/TPM entry point must reject an unsafe device path
// BEFORE shelling out. We drive a flag-shaped path through the real
// functions and require ErrInvalidDevicePath — proving the guard runs at
// the boundary, not just in the helper.
func TestLUKSEntryPoints_RejectFlagShapedDevicePath(t *testing.T) {
	SetBackend(BackendLUKS)
	ctx := context.Background()
	const evil = "--header=/tmp/evil"

	checks := map[string]func() error{
		"IsLuks":         func() error { _, err := IsLuks(ctx, evil); return err },
		"AddKey":         func() error { return AddKey(ctx, evil, "old", "new") },
		"AddKeyToSlot":   func() error { return AddKeyToSlot(ctx, evil, 0, "old", "new") },
		"RemoveKey":      func() error { return RemoveKey(ctx, evil, "key") },
		"KillSlot":       func() error { return KillSlot(ctx, evil, 0, "old") },
		"TestPassphrase": func() error { _, err := TestPassphrase(ctx, evil, "pw"); return err },
		"EnrollTPM":      func() error { return EnrollTPM(ctx, evil, "old") },
		"WipeTPM":        func() error { return WipeTPM(ctx, evil, "old") },
	}
	for name, call := range checks {
		err := call()
		if !errors.Is(err, ErrInvalidDevicePath) {
			t.Errorf("%s(%q) error = %v, want ErrInvalidDevicePath", name, evil, err)
		}
	}
}
