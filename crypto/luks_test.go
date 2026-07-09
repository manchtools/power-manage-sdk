package crypto

import (
	"bytes"
	"testing"
)

// SealLuksPassphrase → OpenLuksPassphrase round-trips under matching context,
// and any context mismatch (device or action) fails to open. As with LPS,
// the two sides derive AAD and info only through these helpers, so this test
// IS the agent↔server cross-repo agreement (spec 25).
func TestLuksPassphrase_RoundTripAndContextBinding(t *testing.T) {
	priv := genRecipient(t)
	const (
		dev = "01HKDEVICE0000000000000000"
		act = "01HKACTION0000000000000000"
		pw  = "luks-D1sk-Passphrase-9f2"
	)

	sealed, err := SealLuksPassphrase(priv.PublicKey(), pw, dev, act)
	if err != nil {
		t.Fatalf("SealLuksPassphrase: %v", err)
	}
	if len(sealed) < MinSealedLen {
		t.Errorf("sealed blob shorter than MinSealedLen: %d < %d", len(sealed), MinSealedLen)
	}
	if bytes.Contains(sealed, []byte(pw)) {
		t.Error("sealed blob contains the plaintext passphrase")
	}

	got, err := OpenLuksPassphrase(priv, sealed, dev, act)
	if err != nil {
		t.Fatalf("OpenLuksPassphrase: %v", err)
	}
	if got != pw {
		t.Errorf("round-trip mismatch: got %q want %q", got, pw)
	}

	mismatches := []struct {
		name     string
		dev, act string
	}{
		{"wrong device", "01HKOTHER00000000000000000", act},
		{"wrong action", dev, "01HKOTHER00000000000000000"},
	}
	for _, m := range mismatches {
		t.Run(m.name, func(t *testing.T) {
			if _, err := OpenLuksPassphrase(priv, sealed, m.dev, m.act); err == nil {
				t.Error("expected context-mismatch open to fail")
			}
		})
	}

	t.Run("tampered blob fails", func(t *testing.T) {
		bad := append([]byte(nil), sealed...)
		bad[len(bad)-1] ^= 0x01
		if _, err := OpenLuksPassphrase(priv, bad, dev, act); err == nil {
			t.Error("expected tampered blob to fail authentication")
		}
	})

	t.Run("wrong key fails", func(t *testing.T) {
		other := genRecipient(t)
		if _, err := OpenLuksPassphrase(other, sealed, dev, act); err == nil {
			t.Error("expected wrong-key open to fail")
		}
	})
}

// TestLuksLpsDomainSeparation pins spec 25 AC 4: a blob sealed under the LPS
// domain must not open under the LUKS domain and vice versa, even with the
// same key and overlapping context values — the distinct HKDF info (and AAD
// shape) enforce it. Without this, a gateway could replay an LPS blob into
// the LUKS store path (or vice versa).
func TestLuksLpsDomainSeparation(t *testing.T) {
	priv := genRecipient(t)
	const (
		dev = "01HKDEVICE0000000000000000"
		act = "01HKACTION0000000000000000"
	)

	t.Run("LPS blob rejected under LUKS domain", func(t *testing.T) {
		// Username "luks" makes the LPS AAD (dev|act|luks) byte-identical to
		// the LUKS AAD — the WORST case, where only the HKDF info separates
		// the domains.
		sealed, err := SealLpsPassword(priv.PublicKey(), "secret-A", dev, act, "luks")
		if err != nil {
			t.Fatalf("SealLpsPassword: %v", err)
		}
		if _, err := OpenLuksPassphrase(priv, sealed, dev, act); err == nil {
			t.Error("LPS-sealed blob opened under the LUKS domain — domain separation broken")
		}
	})

	t.Run("LUKS blob rejected under LPS domain", func(t *testing.T) {
		sealed, err := SealLuksPassphrase(priv.PublicKey(), "secret-B", dev, act)
		if err != nil {
			t.Fatalf("SealLuksPassphrase: %v", err)
		}
		if _, err := OpenLpsPassword(priv, sealed, dev, act, "luks"); err == nil {
			t.Error("LUKS-sealed blob opened under the LPS domain — domain separation broken")
		}
	})
}

// TestSeal_EmptySecretFailsFast pins the fail-fast on an empty secret for
// BOTH seal domains: an empty plaintext would seal to a blob one byte below
// MinSealedLen and die at a wire validator with a confusing error instead.
func TestSeal_EmptySecretFailsFast(t *testing.T) {
	priv := genRecipient(t)
	const (
		dev = "01HKDEVICE0000000000000000"
		act = "01HKACTION0000000000000000"
	)
	if _, err := SealLuksPassphrase(priv.PublicKey(), "", dev, act); err == nil {
		t.Error("expected SealLuksPassphrase with empty passphrase to fail fast")
	}
	if _, err := SealLpsPassword(priv.PublicKey(), "", dev, act, "alice"); err == nil {
		t.Error("expected SealLpsPassword with empty password to fail fast")
	}
}

// TestSealLuksPassphrase_RequiresContext refuses empty device/action — a
// partial AAD would bind loosely (mirrors the LPS context rule).
func TestSealLuksPassphrase_RequiresContext(t *testing.T) {
	priv := genRecipient(t)
	cases := []struct {
		name     string
		dev, act string
	}{
		{"empty device", "", "01HKACTION0000000000000000"},
		{"empty action", "01HKDEVICE0000000000000000", ""},
		{"both empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := SealLuksPassphrase(priv.PublicKey(), "pw", c.dev, c.act); err == nil {
				t.Error("expected seal with incomplete context to fail")
			}
			if _, err := OpenLuksPassphrase(priv, []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), c.dev, c.act); err == nil {
				t.Error("expected open with incomplete context to fail")
			}
		})
	}
}
