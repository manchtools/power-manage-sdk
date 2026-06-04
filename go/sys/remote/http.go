package remote

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// defaultHTTPMaxBytes caps the size of any single HTTP payload to defeat
// zip-bomb / runaway-stream surprises. 2 GiB lines up with the typical
// "large but not crazy" artefact (full distro ISO, big tarball); callers
// who legitimately need more must set MaxBytes explicitly.
const defaultHTTPMaxBytes int64 = 2 * 1024 * 1024 * 1024

// HTTPConfig configures a public-HTTP Source. Authentication is
// deliberately not modelled — v1 is anonymous-only. v2 adds an Auth
// type without breaking this struct's binary layout.
type HTTPConfig struct {
	// URL of the payload. https:// and http:// schemes only; no
	// userinfo, no fragment, no control characters.
	URL string

	// ChecksumSHA256 — optional, hex-encoded (64 chars). When set, the
	// fetched body is hashed during streaming and the result compared
	// against this value; mismatch is ErrIntegrity. Strongly recommended
	// for any production deploy, mandatory in combination with
	// Extract+Prune (a malicious origin could otherwise poison a
	// destructive sync).
	ChecksumSHA256 string

	// Extract — when true, the payload is treated as an archive
	// (tar.gz / zip / tar.xz, detected by Content-Type + filename)
	// and unpacked into the destination directory. When false, the
	// payload is written verbatim to the destination path.
	Extract bool

	// Prune — for archive payloads only. When true, files present
	// locally in the destination but absent from the archive are
	// removed after a successful extract (mirror-with-delete). For
	// single-file payloads this field is invalid (NewHTTP rejects it).
	Prune bool

	// MaxBytes — hard size cap on the streamed body. Zero means
	// defaultHTTPMaxBytes (2 GiB). The cap is enforced via a
	// LimitReader, so exceeding it surfaces as an error before the
	// excess hits disk.
	MaxBytes int64

	// Mode / Owner / Group — applied to the destination after a
	// successful Fetch via sys/fs.SetPermissions. Empty strings leave
	// the OS default in place.
	Mode  string
	Owner string
	Group string
}

// httpSource is the concrete Source implementation. Stored as a value
// (no mutex) — the validated config is immutable after construction.
type httpSource struct {
	parsedURL *url.URL
	cfg       HTTPConfig
	checksum  []byte // decoded ChecksumSHA256; nil when none set
}

// NewHTTP validates cfg and returns a Source. Returns
// ErrInvalidConfig on any validation failure. Fetch / Wipe semantics
// are added by the following slices; this constructor is the surface
// the rest of the package locks in.
func NewHTTP(cfg HTTPConfig) (Source, error) {
	if err := validateHTTPConfig(&cfg); err != nil {
		return nil, err
	}
	parsed, err := parseHTTPURL(cfg.URL)
	if err != nil {
		return nil, err
	}

	var checksum []byte
	if cfg.ChecksumSHA256 != "" {
		b, derr := hex.DecodeString(strings.ToLower(cfg.ChecksumSHA256))
		if derr != nil || len(b) != 32 {
			return nil, fmt.Errorf("%w: checksum_sha256 must be 64 hex chars", ErrInvalidConfig)
		}
		checksum = b
	}

	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultHTTPMaxBytes
	}

	return &httpSource{parsedURL: parsed, cfg: cfg, checksum: checksum}, nil
}

// Fetch — stubbed for Slice 3; the contract here is "constructor works
// in isolation". Slice 4 fills in single-file Fetch, Slice 5 adds the
// archive branch.
func (h *httpSource) Fetch(ctx context.Context, dest string) (Result, error) {
	return Result{}, errors.New("remote: http Fetch unimplemented (slice 4)")
}

// Wipe — stubbed for Slice 3. Slice 6 lands the shared implementation.
func (h *httpSource) Wipe(ctx context.Context, dest string) error {
	return errors.New("remote: http Wipe unimplemented (slice 6)")
}

// String returns a short, human-readable handle used in log lines and
// CommandOutput summaries. Includes the URL (without any future auth
// fields) and a hint about the mode.
func (h *httpSource) String() string {
	mode := "file"
	if h.cfg.Extract {
		mode = "archive"
	}
	return fmt.Sprintf("http %s [%s]", h.cfg.URL, mode)
}

// maxBytes is the effective payload cap after defaulting.
// Package-internal accessor used by the size-cap test in Slice 3 and by
// Fetch in Slice 4.
func (h *httpSource) maxBytes() int64 { return h.cfg.MaxBytes }

func validateHTTPConfig(cfg *HTTPConfig) error {
	if cfg.Prune && !cfg.Extract {
		return fmt.Errorf("%w: prune requires extract", ErrInvalidConfig)
	}
	return nil
}

// parseHTTPURL is the URL validation layer. Refuses everything we don't
// want to support today — non-http(s) schemes, embedded credentials,
// fragments, control characters — so a misconfigured action can't
// silently degrade to "download whatever the parser is willing to make
// of this string".
func parseHTTPURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: url is empty", ErrInvalidConfig)
	}
	if strings.ContainsAny(raw, "\x00\n\r") {
		return nil, fmt.Errorf("%w: url contains control characters", ErrInvalidConfig)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("%w: url is not absolute", ErrInvalidConfig)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("%w: scheme %q not supported (https or http only)", ErrInvalidConfig, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: url must not include userinfo", ErrInvalidConfig)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("%w: url must not include a fragment", ErrInvalidConfig)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: url has no host", ErrInvalidConfig)
	}
	return u, nil
}
