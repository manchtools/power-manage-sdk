package sdk

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateHTTPSURL returns a non-nil error unless raw is a well-formed
// https://host URL. It parses rather than prefix-checks so every corner
// a bare "starts with https://" test misses fails closed:
//
//   - non-https schemes (http, ftp, h2c, the empty scheme)
//   - case variants (HTTP://, Https://) and leading whitespace
//   - opaque forms (https:foo — Opaque != "")
//   - hostless URLs (https:)
//   - embedded user info (https://user:pass@host) and fragments
//
// It is the single source for the agent's https-only trust boundaries —
// the enrollment server_url and the gateway URL — so a cleartext or
// malformed endpoint is refused before any network call.
func ValidateHTTPSURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if strings.ToLower(u.Scheme) != "https" {
		return fmt.Errorf("URL must use https, got scheme %q", u.Scheme)
	}
	if u.Opaque != "" {
		return fmt.Errorf("URL must be https://host, not an opaque URL")
	}
	if u.Host == "" {
		return fmt.Errorf("URL has no host")
	}
	if u.User != nil {
		return fmt.Errorf("URL must not contain user info")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("URL must not contain a fragment")
	}
	return nil
}
