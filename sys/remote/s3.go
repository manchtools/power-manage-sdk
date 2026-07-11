package remote

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// S3Config configures an anonymous-read S3 Source. The endpoint can be
// any S3-compatible HTTP service (AWS, MinIO, R2, Backblaze B2's S3
// gateway, …); v1 only speaks the unauthenticated path-style GET / HEAD
// surface, so the endpoint must serve the object at
// `${endpoint}/${bucket}/${key}` without signing.
//
// Authentication is deliberately not modelled — v1 is anonymous-only.
// v2 adds an Auth type without breaking this struct's binary layout.
type S3Config struct {
	// Endpoint — the base URL of the S3-compatible service.
	// e.g. "https://s3.amazonaws.com" or "https://my-minio:9000".
	Endpoint string

	// Bucket — the bucket name. 1–63 chars, mirroring AWS's published
	// limit; permissive on character set since most S3-compatibles
	// honour the standard rules and surfacing a wrong-bucket later via
	// a server 404 is just as informative.
	Bucket string

	// Key — the object key, OR a prefix ending in "/" for the Slice-12
	// prefix-sync mode. v1 single-key mode uses a non-slash-terminated
	// key.
	Key string

	// Mode / Owner / Group — applied to dest after a successful fetch.
	Mode  string
	Owner string
	Group string

	// Prune — used by the prefix-sync path (Slice 12). For single-key
	// fetches the field is currently a no-op; NewS3 accepts the
	// combination so callers can flip between single and prefix modes
	// without re-validating.
	Prune bool
}

// s3Source is the concrete Source implementation for an anonymous S3
// endpoint. Single-key mode in v1; prefix-sync arrives in Slice 12.
type s3Source struct {
	cfg       S3Config
	objectURL string
	client    *http.Client

	mu       sync.Mutex
	revision string // last successful object ETag
}

// NewS3 validates cfg and returns a Source. Pre-builds the full object
// URL so the Fetch path doesn't re-parse the endpoint every call.
func NewS3(cfg S3Config) (Source, error) {
	if err := validateS3Config(&cfg); err != nil {
		return nil, err
	}
	endpoint, err := parseS3Endpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	full := *endpoint
	full.Path = strings.TrimRight(endpoint.Path, "/") + "/" + cfg.Bucket + "/" + cfg.Key
	return &s3Source{
		cfg:       cfg,
		objectURL: full.String(),
		client:    defaultHTTPClient(RedirectSameOrigin),
	}, nil
}

// Fetch downloads the object to dest. Single-key path only — prefix
// sync lands in Slice 12.
func (s *s3Source) Fetch(ctx context.Context, dest string) (Result, error) {
	if strings.HasSuffix(s.cfg.Key, "/") {
		return s.fetchPrefix(ctx, dest)
	}
	if err := validateDestination(dest); err != nil {
		return Result{}, err
	}

	s.mu.Lock()
	cachedRevision := s.revision
	s.mu.Unlock()

	if cachedRevision != "" {
		notModified, err := s.headNotModified(ctx, cachedRevision)
		if err != nil {
			return Result{}, err
		}
		if notModified {
			return Result{Changed: false, Revision: cachedRevision}, nil
		}
	}

	body, etag, err := s.openObject(ctx, cachedRevision)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = body.Close() }()

	maxBytes := int64(defaultHTTPMaxBytes) // S3 single objects honour the same cap as HTTP for now.
	tmp, written, sum, err := streamToTmp(dest, body, maxBytes)
	if err != nil {
		return Result{}, err
	}

	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return Result{}, fmt.Errorf("rename to %s: %w", dest, err)
	}

	if err := applyMode(dest, s.cfg.Mode, s.cfg.Owner, s.cfg.Group); err != nil {
		return Result{}, err
	}

	revision := etag
	if revision == "" {
		revision = hex.EncodeToString(sum)
	}
	s.mu.Lock()
	s.revision = revision
	s.mu.Unlock()
	RecordDest(dest)

	return Result{
		Changed:      true,
		BytesWritten: written,
		FilesTouched: 1,
		Digest:       hex.EncodeToString(sum),
		Revision:     revision,
	}, nil
}

// Wipe forwards to the shared implementation.
func (s *s3Source) Wipe(ctx context.Context, dest string) error {
	return wipeDest(ctx, dest)
}

// String — short handle for log lines.
func (s *s3Source) String() string {
	return fmt.Sprintf("s3 %s/%s/%s", s.cfg.Endpoint, s.cfg.Bucket, s.cfg.Key)
}

// headNotModified issues a HEAD with If-None-Match. Returns true on
// 304. A 403/404 surfaces as ErrInvalidConfig wrapping the endpoint
// path so the operator knows to open the bucket policy (the most
// common anonymous-S3 footgun).
func (s *s3Source) headNotModified(ctx context.Context, etag string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.objectURL, nil)
	if err != nil {
		return false, fmt.Errorf("HEAD %s: %w", s.objectURL, err)
	}
	req.Header.Set("If-None-Match", etag)
	resp, err := s.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("HEAD %s: %w", s.objectURL, err)
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return true, nil
	case resp.StatusCode == http.StatusOK:
		return false, nil
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return false, fmt.Errorf("%w: anonymous HEAD on %s returned %d (bucket policy may need adjustment)", ErrInvalidConfig, s.objectURL, resp.StatusCode)
	default:
		return false, fmt.Errorf("HEAD %s: status %d", s.objectURL, resp.StatusCode)
	}
}

// openObject issues GET (with If-None-Match if a cached revision is
// known) and returns (body, etag, error). Body is the caller's to
// Close.
func (s *s3Source) openObject(ctx context.Context, etag string) (io.ReadCloser, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.objectURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", s.objectURL, err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", s.objectURL, err)
	}
	switch {
	case resp.StatusCode == http.StatusNotModified:
		_ = resp.Body.Close()
		return io.NopCloser(strings.NewReader("")), resp.Header.Get("ETag"), nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return resp.Body, resp.Header.Get("ETag"), nil
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		_ = resp.Body.Close()
		return nil, "", fmt.Errorf("%w: anonymous GET on %s returned %d (bucket policy may need adjustment)", ErrInvalidConfig, s.objectURL, resp.StatusCode)
	default:
		_ = resp.Body.Close()
		return nil, "", fmt.Errorf("GET %s: status %d", s.objectURL, resp.StatusCode)
	}
}

func validateS3Config(cfg *S3Config) error {
	if strings.TrimSpace(cfg.Bucket) == "" {
		return fmt.Errorf("%w: bucket is required", ErrInvalidConfig)
	}
	if len(cfg.Bucket) > 63 {
		return fmt.Errorf("%w: bucket exceeds 63 chars", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.Key) == "" {
		return fmt.Errorf("%w: key is required", ErrInvalidConfig)
	}
	if len(cfg.Key) > 1024 {
		return fmt.Errorf("%w: key exceeds 1024 chars", ErrInvalidConfig)
	}
	return nil
}

func parseS3Endpoint(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: endpoint is empty", ErrInvalidConfig)
	}
	if strings.ContainsAny(raw, "\x00\n\r") {
		return nil, fmt.Errorf("%w: endpoint contains control characters", ErrInvalidConfig)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("%w: endpoint is not absolute", ErrInvalidConfig)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("%w: endpoint scheme %q not supported", ErrInvalidConfig, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: endpoint must not include userinfo", ErrInvalidConfig)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: endpoint has no host", ErrInvalidConfig)
	}
	return u, nil
}
