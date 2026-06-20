//go:build container

// Container-based real-execution tests for the LUKS Manager. The fake-runner
// unit tests feed cryptsetup's exit codes and output; these run the Manager
// against the REAL cryptsetup binary on a REAL LUKS2 container, so the exit-code
// mapping (incl. the P0.4 "not-LUKS vs error" distinction) and the slot
// lifecycle are verified, not assumed.
//
// No privileged container / loop device is required: cryptsetup does every
// HEADER operation (luksFormat / isLuks / luksAddKey / luksRemoveKey /
// luksKillSlot / open --test-passphrase) directly on a file, and a file under
// /dev/shm satisfies the Manager's validateDevicePath (/dev/ prefix) while being
// an ordinary writable tmpfs path inside the container. (Activation / lsblk
// detection DO need a real block device and are out of scope here.)
//
// Tests self-skip when cryptsetup is absent, so `go test -tags=container` is
// correct against any image.
package encryption

import (
	"context"
	"os"
	osexec "os/exec"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

const containerCtxTimeout = 60 * time.Second

func requireCryptsetup(t *testing.T) {
	t.Helper()
	if _, err := osexec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup not on PATH")
	}
}

// directMgr builds a LUKS Manager on the Direct backend (the container runs as
// root, so cryptsetup needs no escalation wrapper).
func directMgr(t *testing.T) Manager {
	t.Helper()
	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	return mgr(t, r) // mgr (encryption_test.go) = New(LUKS, r)
}

// newDevFile creates an empty `size`-byte file under /dev/shm (a tmpfs path that
// passes validateDevicePath's /dev/ requirement) and registers its cleanup.
func newDevFile(t *testing.T, size int64) string {
	t.Helper()
	f, err := os.CreateTemp("/dev/shm", "pm-test-luks-*.img")
	if err != nil {
		t.Fatalf("create /dev/shm device file (need --shm-size headroom?): %v", err)
	}
	name := f.Name()
	if err := f.Truncate(size); err != nil {
		f.Close()
		os.Remove(name)
		t.Fatalf("truncate device file: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(name) })
	return name
}

// formatLUKS creates a LUKS2 container at a /dev/shm path keyed by passphrase,
// using raw cryptsetup (this is test SETUP, not the code under test). 64 MiB
// leaves room for the ~16 MiB LUKS2 keyslot area plus a little data.
func formatLUKS(t *testing.T, passphrase string) string {
	t.Helper()
	dev := newDevFile(t, 64<<20)
	kf, err := os.CreateTemp(t.TempDir(), "fmt.key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kf.WriteString(passphrase); err != nil {
		t.Fatal(err)
	}
	kf.Close()
	cmd := osexec.Command("cryptsetup", "luksFormat", dev, "--key-file", kf.Name(), "--batch-mode")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setup: cryptsetup luksFormat failed: %v\n%s", err, out)
	}
	return dev
}

// TestIsEncrypted_Container pins the exit-code mapping against real cryptsetup:
// a LUKS2 container is encrypted, a zeroed file is not, and a NONEXISTENT device
// is an ERROR — never (false, nil). The last case is the P0.4 anti-fail-open
// pin: real cryptsetup returns exit 4 (access denied) for a missing device, and
// IsEncrypted must NOT report that as "plaintext".
func TestIsEncrypted_Container(t *testing.T) {
	requireCryptsetup(t)
	m := directMgr(t)
	ctx, cancel := context.WithTimeout(context.Background(), containerCtxTimeout)
	defer cancel()

	if enc, err := m.IsEncrypted(ctx, formatLUKS(t, "fmt-pass")); err != nil || !enc {
		t.Errorf("IsEncrypted(real LUKS) = (%v, %v); want (true, nil)", enc, err)
	}
	if enc, err := m.IsEncrypted(ctx, newDevFile(t, 16<<20)); err != nil || enc {
		t.Errorf("IsEncrypted(zeros) = (%v, %v); want (false, nil)", enc, err)
	}
	if enc, err := m.IsEncrypted(ctx, "/dev/pm-nonexistent-xyz"); err == nil || enc {
		t.Errorf("IsEncrypted(nonexistent) = (%v, %v); want (false, error) — must not fail-open to plaintext", enc, err)
	}
}

// TestVerifyPassphrase_Container pins that a correct passphrase verifies, a
// WRONG one returns (false, nil) — NOT an error (real cryptsetup exit 2) — and a
// missing device is an error.
func TestVerifyPassphrase_Container(t *testing.T) {
	requireCryptsetup(t)
	m := directMgr(t)
	ctx, cancel := context.WithTimeout(context.Background(), containerCtxTimeout)
	defer cancel()
	dev := formatLUKS(t, "right-pass")

	if ok, err := m.VerifyPassphrase(ctx, dev, mustSecret(t, "right-pass")); err != nil || !ok {
		t.Errorf("VerifyPassphrase(correct) = (%v, %v); want (true, nil)", ok, err)
	}
	if ok, err := m.VerifyPassphrase(ctx, dev, mustSecret(t, "wrong-pass")); err != nil || ok {
		t.Errorf("VerifyPassphrase(wrong) = (%v, %v); want (false, nil) — a wrong passphrase is not an error", ok, err)
	}
	if ok, err := m.VerifyPassphrase(ctx, "/dev/pm-nonexistent-xyz", mustSecret(t, "x")); err == nil || ok {
		t.Errorf("VerifyPassphrase(nonexistent) = (%v, %v); want (false, error)", ok, err)
	}
}

// TestKeySlotLifecycle_Container exercises AddKey → RemoveKey end-to-end against
// real cryptsetup: a second key added (authenticated by the first) verifies,
// then after removal stops verifying while the original still works.
func TestKeySlotLifecycle_Container(t *testing.T) {
	requireCryptsetup(t)
	m := directMgr(t)
	ctx, cancel := context.WithTimeout(context.Background(), containerCtxTimeout)
	defer cancel()
	dev := formatLUKS(t, "key-one")
	k1, k2 := mustSecret(t, "key-one"), mustSecret(t, "key-two")

	if err := m.AddKey(ctx, dev, k1, k2, AddKeyOptions{}); err != nil {
		t.Fatalf("AddKey(k2 authed by k1): %v", err)
	}
	if ok, err := m.VerifyPassphrase(ctx, dev, k2); err != nil || !ok {
		t.Fatalf("after AddKey, VerifyPassphrase(k2) = (%v, %v); want true", ok, err)
	}
	if err := m.RemoveKey(ctx, dev, k2); err != nil {
		t.Fatalf("RemoveKey(k2): %v", err)
	}
	if ok, err := m.VerifyPassphrase(ctx, dev, k2); err != nil || ok {
		t.Errorf("after RemoveKey, VerifyPassphrase(k2) = (%v, %v); want false", ok, err)
	}
	if ok, err := m.VerifyPassphrase(ctx, dev, k1); err != nil || !ok {
		t.Errorf("VerifyPassphrase(k1, untouched) = (%v, %v); want true", ok, err)
	}
}

// TestKillSlot_Container pins KillSlot against real cryptsetup: a key added to
// slot 1 stops verifying after that slot is killed, while slot 0 is unaffected.
func TestKillSlot_Container(t *testing.T) {
	requireCryptsetup(t)
	m := directMgr(t)
	ctx, cancel := context.WithTimeout(context.Background(), containerCtxTimeout)
	defer cancel()
	dev := formatLUKS(t, "slot-zero") // occupies slot 0
	k0, k1 := mustSecret(t, "slot-zero"), mustSecret(t, "slot-one")

	if err := m.AddKey(ctx, dev, k0, k1, AddKeyOptions{Slot: ptr(1)}); err != nil {
		t.Fatalf("AddKey(slot 1): %v", err)
	}
	if err := m.KillSlot(ctx, dev, 1, k0); err != nil {
		t.Fatalf("KillSlot(1, authed by k0): %v", err)
	}
	if ok, err := m.VerifyPassphrase(ctx, dev, k1); err != nil || ok {
		t.Errorf("after KillSlot(1), VerifyPassphrase(k1) = (%v, %v); want false", ok, err)
	}
	if ok, err := m.VerifyPassphrase(ctx, dev, k0); err != nil || !ok {
		t.Errorf("VerifyPassphrase(k0, untouched) = (%v, %v); want true", ok, err)
	}
}
