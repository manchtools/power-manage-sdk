// Package remote pulls files or directory trees onto a managed machine
// from a public HTTP URL, a version-controlled repository (Git in v1), or
// an anonymous S3-compatible endpoint. It is the reusable building block
// behind a future ACTION_TYPE_REMOTE_SOURCE; the agent executor for that
// action is intentionally NOT in this package — this primitive can be
// driven from any SDK consumer (CLI, custom tooling, future actions).
//
// Pattern: this package mirrors sdk/go/pkg's interface-+-factory shape
// (Source interface, NewHTTP/NewGit/NewS3 factories, one file per impl).
// It deliberately does NOT use the atomic-backend selector pattern from
// sys/encryption / sys/service, because multiple source types coexist
// per agent run and the choice is per call, not per startup.
//
// Safety surface: every destination is run through
// sys/fs.ResolveAndValidatePath and the IsProtectedPath check before any
// filesystem mutation, archive entries are guarded against ../, absolute
// paths, and escape-symlinks, and HTTP fetches are size-capped to defeat
// zip-bomb-style inputs.
package remote

import (
	"context"
	"errors"
)

// Source is the unified contract every backend implements. Implementations
// must be safe to call from multiple goroutines, though concurrent Fetch
// calls against the same dest will race in the obvious way (last writer
// wins, with the atomic-write guarantees of the individual backends).
type Source interface {
	// Fetch brings the remote content to dest, idempotent on the drift
	// token: a second call against an unchanged upstream returns
	// Changed=false without re-downloading.
	Fetch(ctx context.Context, dest string) (Result, error)

	// Wipe removes dest entirely. Used for desired-state ABSENT.
	// Implementations must refuse paths outside the allow-list documented
	// on the package-level Wipe guard (see paths.go).
	Wipe(ctx context.Context, dest string) error

	// String is a short, human-readable handle ("https://… (sha256)",
	// "git https://… @ main", "s3 endpoint/bucket/key"). Used in log
	// lines and CommandOutput summaries.
	String() string
}

// Result is what every Source returns from Fetch. Callers compare
// Revision against a cached value to short-circuit no-op syncs.
type Result struct {
	// Changed is false when the drift token matched and nothing was
	// written. Callers should treat this as a successful no-op.
	Changed bool

	// BytesWritten is the total payload size copied to dest on this call.
	// Zero when Changed is false.
	BytesWritten int64

	// FilesTouched is the count of leaf files placed or updated.
	// Always 1 for single-file HTTP / S3-key fetches; >1 for archive
	// extraction, Git checkouts, and S3 prefix syncs.
	FilesTouched int

	// Digest is the sha256 of the fetched payload (single file) or the
	// canonicalised tree root (directory). Hex-encoded.
	Digest string

	// Revision is an opaque drift token. HTTP: ETag or
	// content-sha256. Git: commit SHA. S3: object ETag or list-hash.
	// Callers persist this between cycles to enable idempotent re-runs.
	Revision string
}

// Sentinel errors. Callers branch on these with errors.Is.
var (
	// ErrInvalidConfig — the Config struct passed to a New* constructor
	// failed validation (bad URL, conflicting flags, missing required
	// field). Wraps the specific validation message.
	ErrInvalidConfig = errors.New("remote: invalid source config")

	// ErrUnsafeDestination — the destination path failed the path-safety
	// check (relative, traversal, protected prefix, symlink escape) OR an
	// archive entry would have written outside dest.
	ErrUnsafeDestination = errors.New("remote: unsafe destination path")

	// ErrIntegrity — fetched payload failed an integrity check (sha256
	// mismatch, size-cap breach treated as a tamper signal, etc.).
	ErrIntegrity = errors.New("remote: integrity check failed")

	// ErrToolMissing — a runtime tool the implementation needs (e.g. a
	// future shell-out git backend's `git` binary) isn't on PATH.
	// Reserved for the registry pattern in vc.go; go-git itself does not
	// raise this.
	ErrToolMissing = errors.New("remote: required tool missing")

	// ErrBackendNotFound — a registry lookup (e.g. cfg.Driver on
	// GitConfig) named a backend that was never registered.
	ErrBackendNotFound = errors.New("remote: backend not registered")

	// ErrBlockedAddress — an outbound fetch tried to connect to an IP the
	// SSRF guard refuses (loopback, link-local / cloud-metadata, multicast,
	// unspecified, or — when AddrPolicy.BlockPrivate is set — a private
	// range), or a redirect pointed at an unsupported scheme. Enforced at
	// dial time so it also covers redirects and DNS rebinding.
	ErrBlockedAddress = errors.New("remote: blocked address (SSRF guard)")
)
