package sdk

import "testing"

// TestValidateHTTPSURL pins the https-only trust-boundary rule. Invalid
// cases are sourced from intent (a cleartext/opaque/hostless/credential-
// bearing endpoint must fail closed), not from the parser under test.
func TestValidateHTTPSURL(t *testing.T) {
	accept := []string{
		"https://control.example.com",
		"https://control.example.com:8081",
		"https://control.example.com:8081/path",
		"  https://control.example.com  ", // leading/trailing whitespace trimmed
		"Https://control.example.com",     // case-variant scheme normalizes to https
	}
	for _, u := range accept {
		t.Run("ok/"+u, func(t *testing.T) {
			if err := ValidateHTTPSURL(u); err != nil {
				t.Errorf("ValidateHTTPSURL(%q) = %v, want nil", u, err)
			}
		})
	}

	reject := []string{
		"",                           // ABSENT
		"http://control.example.com", // cleartext
		"HTTP://control.example.com", // case variant of cleartext
		"h2c://control.example.com",  // wrong scheme
		"ftp://x",                    // wrong scheme
		"control.example.com",        // scheme-less
		"https:foo",                  // opaque
		"https:",                     // scheme, no host
		"https://",                   // no host
		"https://user:pass@host",     // embedded credentials
		"https://host#frag",          // fragment
	}
	for _, u := range reject {
		t.Run("reject/"+u, func(t *testing.T) {
			if err := ValidateHTTPSURL(u); err == nil {
				t.Errorf("ValidateHTTPSURL(%q) = nil, want error", u)
			}
		})
	}
}
