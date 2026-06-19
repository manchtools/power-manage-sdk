// Package remote pulls files or directory trees onto a managed machine
// from one of three sources: a public HTTP URL, a version-controlled
// repository (Git in v1, with a pluggable interface for future drivers),
// or an anonymous S3-compatible endpoint.
//
// It is the reusable building block behind a future
// ACTION_TYPE_REMOTE_SOURCE action — the agent executor for that action
// is intentionally NOT in this package. Anything that drives a Source
// (a CLI, a custom tool, a future action) gets idempotent fetches,
// drift detection, atomic placement, and the same safety guarantees
// without re-implementing them.
//
// # Usage
//
// All three sources implement the Source interface:
//
//	type Source interface {
//	    Fetch(ctx context.Context, dest string) (Result, error)
//	    Wipe (ctx context.Context, dest string) error
//	    String() string
//	}
//
// Pick a backend via one of the three factories:
//
//	src, err := remote.NewHTTP(remote.HTTPConfig{
//	    URL:            "https://example.test/release.tar.gz",
//	    ChecksumSHA256: "...",
//	    Extract:        true,
//	    Prune:          true,
//	    Mode:           "0644",
//	})
//
//	src, err := remote.NewGit(remote.GitConfig{
//	    URL:  "https://github.com/manchtools/example.git",
//	    Ref:  "v1.0.0",
//	    Prune: true,
//	})
//
//	src, err := remote.NewS3(remote.S3Config{
//	    Endpoint: "https://s3.amazonaws.com",
//	    Bucket:   "my-bucket",
//	    Key:      "config/", // trailing slash → prefix-sync mode
//	    Prune:    true,
//	})
//
// Then drive Fetch / Wipe on the returned Source:
//
//	res, err := src.Fetch(ctx, "/var/lib/power-manage/release")
//	// res.Changed   — true on first fetch, false on a no-op drift hit.
//	// res.Revision  — opaque drift token; cache between cycles to skip
//	//                 no-op re-fetches.
//	// res.Digest    — sha256 of the payload (single file) or the
//	//                 canonicalised tree root (directory).
//
// # Drift detection
//
// Each backend tracks an opaque drift token in Result.Revision. A
// follow-up Fetch with cfg unchanged calls into the cheap probe path:
//
//   - HTTP: HEAD with If-None-Match. 304 → no-op short-circuit.
//   - Git:  ls-remote (no clone). Compares upstream commit SHA against
//     the cached one.
//   - S3:   single key — HEAD with If-None-Match. prefix — paginated
//     list + canonical hash compare.
//
// Drift state is per-process. The intended consumer (the upcoming
// REMOTE_SOURCE action's executor) persists Result.Revision per action
// so the skip survives restarts.
//
// # Safety
//
// Every destination flows through sys/fs.ResolveAndValidatePath plus a
// deny-by-default subtree check (sys/fs.IsUnderProtectedPrefix): any path at
// or under a protected system root — /etc/cron.d/x, /usr/bin/x,
// /home/<u>/.ssh/x, /var/lib/x — is refused at ANY depth, not just the exact
// top-level dir. The only exemptions are the agent-owned managed roots
// (/var/lib/power-manage/, /etc/power-manage/). Wipe additionally requires the
// path to live under one of those managed roots OR to have been seen by a
// successful Fetch (RecordDest), and refuses a protected subtree even if it
// was somehow recorded; a hostile actor with action-creation rights can't
// instruct an agent to write or rm-rf /etc/cron.d by guessing a clever URL.
//
// Archive extraction (HTTP Extract=true) refuses entries that contain
// "..", absolute paths, escape symlinks, NUL bytes, or anything that
// resolves outside the staging dir. The extractor is fuzzed
// (FuzzHTTPArchive_Tar) so adversarial inputs surface as errors, not
// panics or escapes.
//
// HTTP and S3 fetches stream through an io.LimitReader capped at
// HTTPConfig.MaxBytes / defaultHTTPMaxBytes (2 GiB) to defeat
// zip-bomb-style inputs.
//
// # Pluggable version-control backends
//
// The version-controlled Source is built on top of
// VersionControlBackend, an interface every driver implements. v1
// ships one driver — github.com/go-git/go-git/v5, registered as
// "go-git" — but the contract is deliberately not git-named. A future
// release can register additional drivers (a shell-out git, Mercurial,
// Fossil) without proto change or downstream API churn:
//
//	type MyDriver struct{}
//	func (MyDriver) CloneOrSync(ctx, cfg, dest) (Result, error) { ... }
//	func (MyDriver) Resolve   (ctx, cfg)       (string, error) { ... }
//
//	func init() {
//	    remote.RegisterVersionControlBackend("my-vcs", MyDriver{})
//	}
//
// Callers select the driver via GitConfig.Driver. Empty string
// normalises to "go-git".
//
// # Known limitations (v1)
//
//   - Public sources only. None of the Config structs carry auth
//     fields. v2 adds optional Auth types per source — additive and
//     binary-compatible with v1 callers.
//   - HTTP archive extraction supports tar.gz and zip. tar.xz is
//     recognised and refused explicitly (the pure-Go xz dep is
//     deferred to v2).
//   - Anonymous S3 listing relies on the bucket's policy allowing
//     unauthenticated ?list-type=2. Not every endpoint does even when
//     individual objects are world-readable. A 403 surfaces as
//     ErrInvalidConfig wrapping the URL so the operator knows where
//     to look.
//   - Git submodules + Prune interact in a "best effort" way; go-git's
//     submodule cleanup is shallow. Documented as a known limitation;
//     deeper handling is a v2 ticket.
//   - HTTP archive Fetch is a strict mirror (staging-swap on every
//     successful extract). The Prune flag is currently a no-op for the
//     HTTP archive branch; an additive-overlay mode that honours
//     Prune=false explicitly is a v2 follow-up.
package remote
