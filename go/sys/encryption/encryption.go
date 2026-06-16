// Package encryption manages disk encryption through an injected exec.Runner.
//
// Build a Manager for an explicit backend (LUKS is the only one today) and a
// Runner, then call its methods. Passphrases and keys are exec.Secret values:
// they are written to an ephemeral /dev/shm key file (or piped via stdin for
// TPM enrollment) and never appear in a command's argv.
//
//	r, _ := exec.NewRunner(exec.Direct)
//	enc, _ := encryption.New(encryption.LUKS, r)
//	ok, _ := enc.VerifyPassphrase(ctx, "/dev/sda2", pass)
//
// Pure helpers (passphrase generation/validation/hashing) are package-level.
package encryption

import (
	"context"
	"fmt"
	"regexp"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// Backend selects the disk-encryption implementation. Passed explicitly even
// though LUKS is the only value today; the zero value is invalid
// (New → ErrUnknownBackend). The never-implemented GELI/CGD scaffolds are not
// ported.
type Backend int

// LUKS is the cryptsetup/LUKS2 implementation.
const LUKS Backend = iota + 1

// ErrUnknownBackend is returned by New for the zero value or any Backend the SDK
// does not implement (fail-closed).
var ErrUnknownBackend = fmt.Errorf("encryption: unknown backend")

// Volume is a detected LUKS volume.
type Volume struct {
	DevicePath string // e.g. "/dev/sda2"
	MapperName string // e.g. "luks-…" (empty if locked)
	MountPoint string // mount point of the unlocked mapper (empty if locked)
}

// AddKeyOptions configures AddKey. The zero value (Slot nil) lets cryptsetup
// auto-assign a free keyslot; set Slot to target a specific one (0..7) — note
// the explicit slot 0 is distinct from auto.
type AddKeyOptions struct {
	Slot *int
}

// Manager is the disk-encryption contract.
type Manager interface {
	IsEncrypted(ctx context.Context, dev string) (bool, error)
	AddKey(ctx context.Context, dev string, existing, newKey exec.Secret, opts AddKeyOptions) error
	RemoveKey(ctx context.Context, dev string, key exec.Secret) error
	KillSlot(ctx context.Context, dev string, slot int, existing exec.Secret) error
	VerifyPassphrase(ctx context.Context, dev string, p exec.Secret) (bool, error)
	DetectVolume(ctx context.Context) (Volume, error)
	DetectVolumeByKey(ctx context.Context, p exec.Secret) (Volume, error)
	DetectAllVolumes(ctx context.Context) ([]Volume, error)
	// TPM returns the TPM enroller for this backend; ok is false when the
	// backend has no TPM support.
	TPM() (TPMEnroller, bool)
}

// TPMEnroller enrolls/removes a TPM2-bound key for a volume.
type TPMEnroller interface {
	Available(ctx context.Context) (bool, error)
	Enroll(ctx context.Context, dev string, existing exec.Secret) error
	Wipe(ctx context.Context, dev string, existing exec.Secret) error
}

// Option is the functional-option type for backend-specific knobs (none today).
type Option func(*luks)

// New returns a Manager for the named backend, driven by runner. Pure: validates
// the backend is known; it does not probe the host. The zero value and any
// unimplemented backend are rejected with ErrUnknownBackend.
func New(b Backend, runner exec.Runner, _ ...Option) (Manager, error) {
	if b != LUKS {
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
	if runner == nil {
		return nil, fmt.Errorf("encryption: runner is required")
	}
	return &luks{r: runner}, nil
}

// validDevicePath restricts device paths to absolute /dev/ entries with a safe
// charset. The leading "/dev/" means a path can never be flag-shaped, and the
// charset rejects whitespace / shell metacharacters; ".." is rejected
// separately. Covers /dev/sdaN, /dev/nvme…, /dev/mapper/…, /dev/disk/by-*.
var validDevicePath = regexp.MustCompile(`^/dev/[a-zA-Z0-9/_.\-]+$`)

func validateDevicePath(dev string) error {
	if !validDevicePath.MatchString(dev) || containsDotDot(dev) {
		return fmt.Errorf("invalid device path %q: must be an absolute /dev/ path with no '..'", dev)
	}
	return nil
}

func containsDotDot(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '.' && s[i+1] == '.' {
			return true
		}
	}
	return false
}
