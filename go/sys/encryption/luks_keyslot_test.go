package encryption

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// These tests pin audit finding #10's keyslot half — LUKS slot
// indices outside [0, 7] must be refused at the SDK boundary, not
// passed through to cryptsetup with an opaque error.

func TestValidateKeySlot_AcceptsValidRange(t *testing.T) {
	for slot := LuksMinKeySlot; slot <= LuksMaxKeySlot; slot++ {
		if err := validateKeySlot(slot); err != nil {
			t.Fatalf("validateKeySlot(%d) = %v; want nil", slot, err)
		}
	}
}

func TestValidateKeySlot_RejectsOutOfRange(t *testing.T) {
	for _, slot := range []int{-1, 8, 9, 100, 1 << 30} {
		t.Run(itoa(slot), func(t *testing.T) {
			err := validateKeySlot(slot)
			if !errors.Is(err, ErrInvalidKeySlot) {
				t.Fatalf("validateKeySlot(%d) = %v; want ErrInvalidKeySlot", slot, err)
			}
			if !strings.Contains(err.Error(), "0..7") {
				t.Errorf("error %q should name the valid range", err)
			}
		})
	}
}

// TestAddKeyToSlot_RejectsBadSlot proves the validation fires before
// the cryptsetup command runs. We pick the LUKS backend so the
// requireBackend gate passes, then assert the error is the slot
// error, not a downstream cryptsetup invocation failure.
func TestAddKeyToSlot_RejectsBadSlot(t *testing.T) {
	original := CurrentBackend()
	SetBackend(BackendLUKS)
	t.Cleanup(func() { SetBackend(original) })

	err := AddKeyToSlot(context.Background(), "/dev/null", 99, "old", "new")
	if !errors.Is(err, ErrInvalidKeySlot) {
		t.Fatalf("AddKeyToSlot with slot 99 = %v; want ErrInvalidKeySlot", err)
	}
}

func TestKillSlot_RejectsBadSlot(t *testing.T) {
	original := CurrentBackend()
	SetBackend(BackendLUKS)
	t.Cleanup(func() { SetBackend(original) })

	err := KillSlot(context.Background(), "/dev/null", -1, "old")
	if !errors.Is(err, ErrInvalidKeySlot) {
		t.Fatalf("KillSlot with slot -1 = %v; want ErrInvalidKeySlot", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
