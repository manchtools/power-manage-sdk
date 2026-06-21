package remote

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
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
	// payload is written verbatim to the destination path. Slice 5
	// introduces this branch; Slice 4 covers the !Extract path.
	Extract bool

	// Prune — for archive payloads only. When true, files present
	// locally in the destination but absent from the archive are
	// removed after a successful extract (mirror-with-delete). For
	// single-file payloads this field is invalid (NewHTTP rejects it).
	Prune bool

	// MaxBytes — hard size cap on the streamed body. Zero means
	// defaultHTTPMaxBytes (2 GiB). The cap is enforced via a one-byte
	// over-read sentinel, so a runaway stream surfaces as ErrIntegrity
	// before the excess hits disk.
	MaxBytes int64

	// Mode / Owner / Group — applied to the destination after a
	// successful Fetch via os.Chmod / sys/fs.FchownNoFollow. Empty
	// strings leave the OS default in place.
	Mode  string
	Owner string
	Group string
}

// httpSource is the concrete Source implementation.
type httpSource struct {
	parsedURL *url.URL
	cfg       HTTPConfig
	checksum  []byte // decoded ChecksumSHA256; nil when none set
	client    *http.Client

	mu       sync.Mutex
	revision string // last successful ETag — drives drift detection
}

// NewHTTP validates cfg and returns a Source. Returns ErrInvalidConfig
// on any validation failure.
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

	return &httpSource{
		parsedURL: parsed,
		cfg:       cfg,
		checksum:  checksum,
		client:    defaultHTTPClient(),
	}, nil
}

// Fetch downloads the payload to dest. Single-file path only — the
// archive branch lands in Slice 5.
//
// Flow:
//  1. Validate dest. Path safety errors short-circuit before any network
//     round-trip so a misconfigured action can't reveal anything via
//     timing.
//  2. If a previous Revision is known, issue a HEAD with
//     If-None-Match. Origin returns 304 → no-op short-circuit, no GET.
//  3. GET (also with If-None-Match in case the HEAD path was skipped).
//  4. Stream the body to <dest>.tmp.<rand> through a LimitReader (cap
//     +1 to detect overrun) and a sha256.Hash. Cancel + clean up on any
//     mid-stream error.
//  5. Verify the optional sha256 pin.
//  6. os.Rename to dest — gives the atomic-write guarantee.
//  7. Apply mode (and, in real deployments, owner/group via
//     sys/fs.FchownNoFollow when running with privilege).
//  8. RecordDest(dest) so a follow-up Wipe can reach it even when dest
//     lives outside the project-managed prefixes.
func (h *httpSource) Fetch(ctx context.Context, dest string) (Result, error) {
	if h.cfg.Extract {
		if httpArchiveDispatch == nil {
			return Result{}, errFetchArchiveUnimplemented
		}
		return httpArchiveDispatch(ctx, h, dest)
	}
	if err := validateDestination(dest); err != nil {
		return Result{}, err
	}

	h.mu.Lock()
	cachedRevision := h.revision
	h.mu.Unlock()

	if cachedRevision != "" {
		notModified, err := h.checkNotModified(ctx, cachedRevision)
		if err != nil {
			return Result{}, err
		}
		if notModified {
			return Result{Changed: false, Revision: cachedRevision}, nil
		}
	}

	body, etag, err := h.openBody(ctx, cachedRevision)
	if err != nil {
		return Result{}, err
	}
	defer body.Close()

	tmp, written, sum, err := streamToTmp(dest, body, h.cfg.MaxBytes)
	if err != nil {
		return Result{}, err
	}

	if h.checksum != nil && subtle.ConstantTimeCompare(sum, h.checksum) != 1 {
		// Stream succeeded but the integrity pin failed; nuke the tmp
		// so a partial / poisoned payload never reaches dest.
		_ = os.Remove(tmp)
		return Result{}, fmt.Errorf("%w: sha256 mismatch for %s", ErrIntegrity, dest)
	}

	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return Result{}, fmt.Errorf("rename to %s: %w", dest, err)
	}

	if err := applyMode(dest, h.cfg.Mode, h.cfg.Owner, h.cfg.Group); err != nil {
		return Result{}, err
	}

	revision := etag
	if revision == "" {
		// Origin omitted ETag — use the content sha256 as the drift
		// token. Loses HEAD short-circuit on the next call (no header
		// to send) but still tells callers whether the body changed.
		revision = hex.EncodeToString(sum)
	}

	h.mu.Lock()
	h.revision = revision
	h.mu.Unlock()

	RecordDest(dest)

	return Result{
		Changed:      true,
		BytesWritten: written,
		FilesTouched: 1,
		Digest:       hex.EncodeToString(sum),
		Revision:     revision,
	}, nil
}

// Wipe forwards to the shared wipeDest implementation.
func (h *httpSource) Wipe(ctx context.Context, dest string) error {
	return wipeDest(ctx, dest)
}

// String returns a short, human-readable handle used in log lines and
// CommandOutput summaries.
func (h *httpSource) String() string {
	mode := "file"
	if h.cfg.Extract {
		mode = "archive"
	}
	return fmt.Sprintf("http %s [%s]", h.cfg.URL, mode)
}

// maxBytes is the effective payload cap after defaulting. Test hook.
func (h *httpSource) maxBytes() int64 { return h.cfg.MaxBytes }

// checkNotModified issues a HEAD with If-None-Match. Returns true on
// a 304 response (the origin confirms the cached Revision is still
// current). Network errors propagate; non-200/304 responses are
// treated as "needs GET" (no-op).
func (h *httpSource) checkNotModified(ctx context.Context, etag string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, h.cfg.URL, nil)
	if err != nil {
		return false, fmt.Errorf("HEAD %s: %w", h.cfg.URL, err)
	}
	req.Header.Set("If-None-Match", etag)
	resp, err := h.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("HEAD %s: %w", h.cfg.URL, err)
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusNotModified, nil
}

// openBody fires a GET (with optional If-None-Match) and returns the
// response body + the origin's ETag (for the next-call drift token).
// Caller must Close the body.
func (h *httpSource) openBody(ctx context.Context, etag string) (io.ReadCloser, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.cfg.URL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", h.cfg.URL, err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", h.cfg.URL, err)
	}
	if resp.StatusCode == http.StatusNotModified {
		// Server-side optimisation rather than client-side error.
		// Equivalent to a cache-hit; return an empty body so the
		// caller falls through to "no body to read" path. In practice
		// we only reach this branch after our own cachedRevision lost
		// the race, which is rare but worth handling cleanly.
		resp.Body.Close()
		return io.NopCloser(strings.NewReader("")), resp.Header.Get("ETag"), nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, "", fmt.Errorf("GET %s: status %d", h.cfg.URL, resp.StatusCode)
	}
	return resp.Body, resp.Header.Get("ETag"), nil
}

// streamToTmp writes the body to "<dest>.tmp.<rand>" through a
// LimitReader and a sha256.Hash. Returns (tmpPath, bytesWritten,
// sumBytes, error). On error the tmp file is removed before returning;
// the returned tmpPath is empty in that case so the caller can't
// accidentally reference a non-existent path.
func streamToTmp(dest string, body io.Reader, maxBytes int64) (string, int64, []byte, error) {
	tmp, err := tmpPathFor(dest)
	if err != nil {
		return "", 0, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(tmp), 0o755); err != nil {
		return "", 0, nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(tmp), err)
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		// EEXIST is possible if a previous run died between OpenFile
		// and Rename. Stomp on it — same caller, same logical fetch.
		if errors.Is(err, os.ErrExist) {
			_ = os.Remove(tmp)
			f, err = os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o600)
		}
		if err != nil {
			return "", 0, nil, fmt.Errorf("open tmp %s: %w", tmp, err)
		}
	}
	cleanup := func() {
		f.Close()
		_ = os.Remove(tmp)
	}

	// LimitReader caps at maxBytes+1 so a one-byte over-read tells us
	// the origin tried to deliver more than we allow.
	limited := io.LimitReader(body, maxBytes+1)
	h := sha256.New()
	tee := io.TeeReader(limited, h)
	n, err := io.Copy(f, tee)
	if err != nil {
		cleanup()
		return "", 0, nil, fmt.Errorf("stream to %s: %w", tmp, err)
	}
	if n > maxBytes {
		cleanup()
		return "", 0, nil, fmt.Errorf("%w: payload exceeds %d bytes", ErrIntegrity, maxBytes)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return "", 0, nil, fmt.Errorf("fsync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", 0, nil, fmt.Errorf("close %s: %w", tmp, err)
	}
	return tmp, n, h.Sum(nil), nil
}

// tmpPathFor builds an unpredictable sibling tmp filename. Sixteen random hex
// chars keep collisions astronomically unlikely while keeping the suffix short
// enough that ext4's 255-char filename limit doesn't bite. The entropy read is
// fail-closed: if crypto/rand cannot produce randomness the suffix would be
// predictable, letting an attacker pre-create a symlink at the staging path, so
// the error is propagated rather than discarded.
func tmpPathFor(dest string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate staging-file suffix: %w", err)
	}
	return dest + ".tmp." + hex.EncodeToString(b[:]), nil
}

// applyMode sets mode and/or ownership on the freshly-written destination, which
// may be a regular file (single-file fetch) OR a directory (archive extract, git
// clone, S3 prefix). Mode is applied with a local chmod (no privilege needed).
// Ownership is applied through sys/fs's fd-anchored, symlink-refusing primitives
// — FchownNoFollow for a regular file, OpenRealDir+Chown for a directory (the
// former refuses non-regular files, so directories MUST take the dir path) — and
// requires CAP_CHOWN (the root agent has it). Empty fields are skipped.
func applyMode(dest, mode, owner, group string) error {
	if mode == "" && owner == "" && group == "" {
		return nil
	}
	if mode != "" {
		// ParseUint(base 8) handles octal mode strings with or without a leading
		// zero ("755", "0755", "0"); do NOT strip a leading "0" first — that turns
		// "0" into "" and wrongly rejects octal zero.
		bits, perr := strconv.ParseUint(mode, 8, 32)
		if perr != nil {
			return fmt.Errorf("invalid mode %q: %w", mode, perr)
		}
		if err := os.Chmod(dest, os.FileMode(bits)); err != nil {
			return fmt.Errorf("chmod %s: %w", dest, err)
		}
	}
	if owner != "" || group != "" {
		uid, gid, err := sysfs.ResolveOwnership(owner, group)
		if err != nil {
			return fmt.Errorf("resolve ownership for %s: %w", dest, err)
		}
		if err := chownNoFollow(dest, uid, gid); err != nil {
			return fmt.Errorf("set ownership on %s: %w", dest, err)
		}
	}
	return nil
}

// chownNoFollow applies ownership to dest without following a final symlink,
// dispatching by inode type: a directory goes through an O_NOFOLLOW|O_DIRECTORY
// fd (OpenRealDir), a regular file through FchownNoFollow. A symlink at dest is
// refused by both paths rather than dereferenced.
func chownNoFollow(dest string, uid, gid int) error {
	info, err := os.Lstat(dest)
	if err != nil {
		return err
	}
	if info.IsDir() {
		d, err := sysfs.OpenRealDir(dest)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Chown(uid, gid)
	}
	return sysfs.FchownNoFollow(dest, uid, gid)
}

// defaultHTTPClient — modest timeouts so a Fetch can't hang forever, and
// no automatic redirect following on by default? Actually leave Go's
// default 10-redirect chase in place: legitimate CDNs (Cloudflare, GH
// releases) use it heavily, and the URL validation already restricts
// the scheme to http/https.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Minute,
		// Refuse any redirect that changes the origin (scheme OR host:port). A
		// download is pinned to a URL; letting a redirect choose a different host
		// lets a compromised origin substitute the bytes (and is an SSRF vector
		// toward internal services), and a scheme change is a TLS downgrade
		// (https -> http) that strips transport integrity from a pinned source.
		// Same-origin path redirects are allowed but bounded.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host) {
				return fmt.Errorf("%w: refusing cross-origin redirect %s://%s -> %s://%s", ErrInvalidConfig,
					via[0].URL.Scheme, via[0].URL.Host, req.URL.Scheme, req.URL.Host)
			}
			if len(via) >= 10 {
				return fmt.Errorf("%w: stopped after 10 redirects", ErrInvalidConfig)
			}
			return nil
		},
	}
}

func validateHTTPConfig(cfg *HTTPConfig) error {
	if cfg.Prune && !cfg.Extract {
		return fmt.Errorf("%w: prune requires extract", ErrInvalidConfig)
	}
	// extract+prune DELETES pre-existing files in the destination tree, so a
	// poisoned origin could weaponize it; require an integrity pin so the bytes
	// that drive the prune are verified before anything is removed.
	if cfg.Extract && cfg.Prune && cfg.ChecksumSHA256 == "" {
		return fmt.Errorf("%w: extract+prune requires a checksum_sha256 (the prune deletes files; the payload must be integrity-pinned)", ErrInvalidConfig)
	}
	// A negative byte cap is a caller error; never silently fall back to the
	// default (which would lift the intended limit).
	if cfg.MaxBytes < 0 {
		return fmt.Errorf("%w: max_bytes must not be negative", ErrInvalidConfig)
	}
	if err := validateModeBits(cfg.Mode); err != nil {
		return err
	}
	return nil
}

// validateModeBits rejects a Mode that sets the setuid/setgid/sticky bits on a
// downloaded artifact — a downloaded setuid-root helper is a privilege-escalation
// dropper. Empty Mode is allowed (no chmod). The octal parsing mirrors applyMode.
func validateModeBits(mode string) error {
	if mode == "" {
		return nil
	}
	// ParseUint(base 8) accepts a leading zero; do NOT TrimPrefix "0" first (it
	// turns "0" into "" and wrongly rejects octal zero). Mirrors applyMode.
	bits, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return fmt.Errorf("%w: invalid mode %q", ErrInvalidConfig, mode)
	}
	if bits&0o7000 != 0 { // setuid(4000) | setgid(2000) | sticky(1000)
		return fmt.Errorf("%w: mode %q sets privileged bits (setuid/setgid/sticky), refused for a downloaded artifact", ErrInvalidConfig, mode)
	}
	return nil
}

// parseHTTPURL is the URL validation layer.
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
