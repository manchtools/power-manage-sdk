package remote

import (
	"context"
	"fmt"
	"sync"
)

// GitConfig configures a version-controlled Source. The struct stays
// here (next to VersionControlBackend) because the interface accepts
// it; NewGit (Slice 9) layers the validation and factory wiring on top.
//
// Authentication is deliberately not modelled — v1 is anonymous-only.
// v2 adds an Auth type without breaking this struct's binary layout.
type GitConfig struct {
	// URL of the repository. https:// only for v1; the constructor
	// rejects ssh / git / file schemes.
	URL string

	// Ref to check out — branch, tag, or commit SHA. Empty string
	// normalises to "main" at construction time.
	Ref string

	// Submodules controls submodule recursion during CloneOrSync. The
	// go-git driver in v1 best-effort handles submodules; the
	// Prune-vs-submodules interaction is intentionally not specified
	// (see Slice 13 doc.go).
	Submodules bool

	// Owner / Group — applied to the dest tree after CloneOrSync via
	// os.Chmod / sys/fs.FchownNoFollow. Empty strings leave the OS default.
	Owner string
	Group string

	// Prune forwards to the backend's "clean untracked files" step.
	// For Git this means a worktree.Clean after checkout.
	Prune bool

	// Driver picks the registered VersionControlBackend by name.
	// Empty string normalises to "go-git" at construction time.
	Driver string
}

// VersionControlBackend is the abstraction every version-controlled
// source driver implements. Git via go-git is the v1 driver; a future
// release could add a shell-out "git-binary" backend, a Mercurial /
// Fossil backend, etc., by Register-ing under a new name.
//
// The interface is deliberately NOT git-named. It's modelled on the
// "clone or sync to a working tree at a named revision" contract that
// Git, Mercurial, Fossil, and Bazaar all support — the name reflects
// what the operation *does*, not which implementation does it.
//
// Implementations must be safe for concurrent use across different
// (URL, dest) pairs. Concurrent calls against the same dest race in
// the obvious way and the caller is responsible for serialising.
type VersionControlBackend interface {
	// CloneOrSync brings the repo at cfg.URL to dest, checked out at
	// cfg.Ref. Idempotent on the revision: calling twice with cfg
	// unchanged leaves dest unchanged and returns Result.Changed=false.
	CloneOrSync(ctx context.Context, cfg GitConfig, dest string) (Result, error)

	// Resolve returns the current upstream revision (commit SHA,
	// changeset hash, etc.) for cfg.Ref without touching dest. Used by
	// gitSource.Fetch to short-circuit no-op pulls when the cached
	// Revision matches.
	Resolve(ctx context.Context, cfg GitConfig) (revision string, err error)
}

// vcRegistry holds every registered version-control backend by
// caller-chosen name. The default driver "go-git" is registered from
// vc_gogit.go's init() (Slice 9); this file only owns the registry
// shape and the lookup contract.
var vcRegistry = struct {
	mu sync.RWMutex
	m  map[string]VersionControlBackend
}{m: make(map[string]VersionControlBackend)}

// RegisterVersionControlBackend adds a named driver to the registry.
// Calls with an empty name OR a nil backend are silently ignored — the
// goal is "registering is safe from any goroutine, including init"
// rather than surfacing programmer errors at startup time, where a
// panic in init can be very hard to diagnose.
//
// Re-registering an existing name overrides the previous entry, which
// is the property tests rely on to swap in a fake backend.
func RegisterVersionControlBackend(name string, b VersionControlBackend) {
	if name == "" || b == nil {
		return
	}
	vcRegistry.mu.Lock()
	defer vcRegistry.mu.Unlock()
	vcRegistry.m[name] = b
}

// versionControlBackend resolves driver to a registered backend.
// Returns ErrBackendNotFound when no backend is registered under that
// name. The name is taken verbatim — no defaulting here; defaulting is
// the constructor's job (NewGit substitutes "go-git" when cfg.Driver
// is empty).
func versionControlBackend(driver string) (VersionControlBackend, error) {
	vcRegistry.mu.RLock()
	b, ok := vcRegistry.m[driver]
	vcRegistry.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrBackendNotFound, driver)
	}
	return b, nil
}
