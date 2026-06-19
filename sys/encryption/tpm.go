package encryption

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// tpmDevicePaths are probed by Available. A var (not const) so tests can point
// it at a temp file (present) or a nonexistent path (absent).
var tpmDevicePaths = []string{"/dev/tpm0", "/dev/tpmrm0"}

// tpmEnroller enrolls/removes a TPM2-bound key via systemd-cryptenroll. The
// authenticating passphrase is piped over stdin, never argv.
type tpmEnroller struct {
	r exec.Runner
}

// Available reports whether a TPM2 device node is present.
func (t *tpmEnroller) Available(ctx context.Context) (bool, error) {
	_ = ctx
	for _, p := range tpmDevicePaths {
		if _, err := os.Stat(p); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// Enroll binds a TPM2 key to dev (PCRs 7+14: Secure Boot + shim/MOK),
// authenticating with existing.
func (t *tpmEnroller) Enroll(ctx context.Context, dev string, existing exec.Secret) error {
	if err := validateDevicePath(dev); err != nil {
		return err
	}
	return t.run(ctx, "enroll", []string{"--tpm2-device=auto", "--tpm2-pcrs=7+14", dev}, existing)
}

// Wipe removes the TPM2 enrollment from dev, authenticating with existing.
func (t *tpmEnroller) Wipe(ctx context.Context, dev string, existing exec.Secret) error {
	if err := validateDevicePath(dev); err != nil {
		return err
	}
	return t.run(ctx, "wipe", []string{"--wipe-slot=tpm2", dev}, existing)
}

// run executes an escalated systemd-cryptenroll command with the passphrase on
// stdin. Reveal() here is the single sanctioned TPM-stdin sink.
func (t *tpmEnroller) run(ctx context.Context, op string, args []string, key exec.Secret) error {
	// Both Enroll and Wipe authenticate with the existing passphrase; an empty
	// one is never a legitimate request, so refuse before any cryptenroll exec.
	if key.IsZero() {
		return fmt.Errorf("%w: empty authenticating passphrase", ErrEmptyKeyMaterial)
	}
	res, err := t.r.Run(ctx, exec.Command{
		Name:     "systemd-cryptenroll",
		Args:     args,
		Stdin:    strings.NewReader(key.Reveal()),
		Escalate: true,
	})
	if err != nil {
		return fmt.Errorf("systemd-cryptenroll %s: %w", op, err)
	}
	if res.ExitCode != 0 {
		return &exec.CommandError{Name: "systemd-cryptenroll", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}
