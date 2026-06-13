package remote

import (
	"errors"
	"strings"
	"testing"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// TestNewHTTP_AcceptsValidConfig — the smoke test for the HTTP factory.
// Locks in that a minimal valid config produces a non-nil Source and no
// error, so later slices can layer Fetch / Wipe semantics on top.
func TestNewHTTP_AcceptsValidConfig(t *testing.T) {
	src, err := NewHTTP(HTTPConfig{URL: "https://example.test/file.txt"})
	if err != nil {
		t.Fatalf("NewHTTP unexpected err: %v", err)
	}
	if src == nil {
		t.Fatal("NewHTTP returned nil Source")
	}
	if got := src.String(); got == "" {
		t.Fatalf("Source.String() empty; want a human-readable handle")
	}
}

// TestNewHTTP_RejectsBadURLs covers the URL-validation contract. Each
// case is a category of malformed input we want to bounce at the door:
// empty, non-absolute, wrong scheme, embedded credentials.
func TestNewHTTP_RejectsBadURLs(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"relative", "file.txt"},
		{"file scheme", "file:///etc/passwd"},
		{"ftp scheme", "ftp://example.test/x"},
		{"javascript scheme", "javascript:alert(1)"},
		{"userinfo present", "https://user:pass@example.test/x"},
		{"with fragment", "https://example.test/x#frag"},
		{"no host", "https:///path-only"},
		{"control chars", "https://example.test/\x00bad"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHTTP(HTTPConfig{URL: tc.url})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewHTTP(%q) = %v; want errors.Is(..., ErrInvalidConfig)", tc.url, err)
			}
		})
	}
}

// TestNewHTTP_RejectsPruneWithoutExtract — Prune is only meaningful when
// the payload is a multi-file archive whose contents are sync-mirrored.
// For a single-file fetch there's nothing to prune, so allowing the
// combination would silently no-op and confuse callers.
func TestNewHTTP_RejectsPruneWithoutExtract(t *testing.T) {
	_, err := NewHTTP(HTTPConfig{
		URL:     "https://example.test/file.tar.gz",
		Extract: false,
		Prune:   true,
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewHTTP(Prune+!Extract) = %v; want errors.Is(..., ErrInvalidConfig)", err)
	}
}

// TestNewHTTP_RejectsPruneWithoutChecksum — Prune is mirror-with-delete,
// so a poisoned origin could drive a destructive local sync. The
// ChecksumSHA256 doc-comment declares it mandatory with Extract+Prune;
// NewHTTP must enforce that rather than leaving it to documentation.
func TestNewHTTP_RejectsPruneWithoutChecksum(t *testing.T) {
	_, err := NewHTTP(HTTPConfig{
		URL:     "https://example.test/dir.tar.gz",
		Extract: true,
		Prune:   true,
		// ChecksumSHA256 deliberately empty.
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewHTTP(Prune without checksum) = %v; want errors.Is(..., ErrInvalidConfig)", err)
	}

	// With a valid checksum the combination is accepted.
	if _, err := NewHTTP(HTTPConfig{
		URL:            "https://example.test/dir.tar.gz",
		Extract:        true,
		Prune:          true,
		ChecksumSHA256: strings.Repeat("a", 64),
	}); err != nil {
		t.Fatalf("NewHTTP(Prune with checksum) = %v; want nil", err)
	}
}

// TestNewHTTP_RejectsBadChecksum — partial / non-hex / wrong-length
// checksum strings get rejected up front so a Fetch never silently runs
// without integrity verification.
func TestNewHTTP_RejectsBadChecksum(t *testing.T) {
	for _, c := range []string{
		"abc",                   // too short
		strings.Repeat("z", 64), // not hex
		strings.Repeat("a", 63), // wrong length
	} {
		t.Run("checksum="+c[:min(len(c), 8)]+"…", func(t *testing.T) {
			_, err := NewHTTP(HTTPConfig{
				URL:            "https://example.test/x",
				ChecksumSHA256: c,
			})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewHTTP(checksum=%q) = %v; want errors.Is(..., ErrInvalidConfig)", c, err)
			}
		})
	}
}

// TestNewHTTP_PreservesConfig — the resolved source should carry the
// caller's URL through to String(), so log lines and CommandOutput
// summaries are useful for debugging without an extra accessor.
func TestNewHTTP_PreservesConfig(t *testing.T) {
	const url = "https://example.test/file.tar.gz"
	src, err := NewHTTP(HTTPConfig{URL: url, Extract: true})
	if err != nil {
		t.Fatalf("NewHTTP err: %v", err)
	}
	if got := src.String(); !contains(got, url) {
		t.Fatalf("Source.String() = %q; want to contain %q", got, url)
	}
}

// TestNewHTTP_DefaultsMaxBytes — MaxBytes=0 normalises to the package
// default (2 GiB). Asserted via the internal accessor so the surface
// stays clean; the cap's effect on actual fetches is covered in Slice 4.
func TestNewHTTP_DefaultsMaxBytes(t *testing.T) {
	src, err := NewHTTP(HTTPConfig{URL: "https://example.test/x"})
	if err != nil {
		t.Fatalf("NewHTTP err: %v", err)
	}
	hs, ok := src.(*httpSource)
	if !ok {
		t.Fatalf("NewHTTP returned %T; want *httpSource", src)
	}
	if got := hs.maxBytes(); got != defaultHTTPMaxBytes {
		t.Fatalf("maxBytes = %d; want %d", got, defaultHTTPMaxBytes)
	}
}
