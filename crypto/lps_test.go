package crypto

import "testing"

// SealLpsPassword → OpenLpsPassword round-trips under matching context, and
// any context field mismatch (device, action, or username) fails to open.
// This pins the exact agent↔server contract: the two sides derive AAD and
// info only through these helpers, so this test IS the cross-repo agreement.
func TestLpsPassword_RoundTripAndContextBinding(t *testing.T) {
	priv := genRecipient(t)
	const (
		dev  = "01HKDEVICE0000000000000000"
		act  = "01HKACTION0000000000000000"
		user = "alice"
		pw   = "R0tated-P@ssw0rd"
	)

	sealed, err := SealLpsPassword(priv.PublicKey(), pw, dev, act, user)
	if err != nil {
		t.Fatalf("SealLpsPassword: %v", err)
	}

	got, err := OpenLpsPassword(priv, sealed, dev, act, user)
	if err != nil {
		t.Fatalf("OpenLpsPassword: %v", err)
	}
	if got != pw {
		t.Errorf("round-trip mismatch: got %q want %q", got, pw)
	}

	mismatches := []struct {
		name           string
		dev, act, user string
	}{
		{"wrong device", "01HKOTHER00000000000000000", act, user},
		{"wrong action", dev, "01HKOTHER00000000000000000", user},
		{"wrong username", dev, act, "bob"},
	}
	for _, m := range mismatches {
		t.Run(m.name, func(t *testing.T) {
			if pt, err := OpenLpsPassword(priv, sealed, m.dev, m.act, m.user); err == nil {
				t.Errorf("opened under %s: got %q, want error", m.name, pt)
			}
		})
	}
}

// An empty context field is refused (ambiguous AAD → no naked seal).
func TestSealLpsPassword_RequiresContext(t *testing.T) {
	priv := genRecipient(t)
	for _, c := range []struct{ dev, act, user string }{
		{"", "a", "u"}, {"d", "", "u"}, {"d", "a", ""},
	} {
		if _, err := SealLpsPassword(priv.PublicKey(), "pw", c.dev, c.act, c.user); err == nil {
			t.Errorf("SealLpsPassword(%q,%q,%q) accepted an empty context field", c.dev, c.act, c.user)
		}
	}
}
