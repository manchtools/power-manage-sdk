package remote

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// gitSource is the version-controlled Source. The struct is intentionally
// thin — the heavy lifting lives in the registered VersionControlBackend
// (vc_gogit.go for v1's go-git driver, others potentially follow).
type gitSource struct {
	cfg     GitConfig
	backend VersionControlBackend

	mu       sync.Mutex
	revision string // last successful upstream SHA, for drift skip in Fetch
}

// NewGit validates cfg, resolves the version-control backend named by
// cfg.Driver (default "go-git"), and returns a Source. Validation
// failures surface as ErrInvalidConfig; an unknown driver surfaces as
// ErrBackendNotFound — both at construction, never deferred to Fetch
// where the caller has already committed to a network round trip.
func NewGit(cfg GitConfig) (Source, error) {
	if err := validateGitConfig(&cfg); err != nil {
		return nil, err
	}
	backend, err := versionControlBackend(cfg.Driver)
	if err != nil {
		return nil, err
	}
	return &gitSource{cfg: cfg, backend: backend}, nil
}

// Fetch is wired in Slice 10; Slice 9 just locks the dispatch path —
// validateDestination then backend.CloneOrSync. The backend stub
// returns "not implemented" until Slice 10 fills it in.
func (g *gitSource) Fetch(ctx context.Context, dest string) (Result, error) {
	if err := validateDestination(dest); err != nil {
		return Result{}, err
	}

	g.mu.Lock()
	cachedRevision := g.revision
	g.mu.Unlock()

	if cachedRevision != "" {
		upstream, err := g.backend.Resolve(ctx, g.cfg)
		if err == nil && upstream == cachedRevision {
			return Result{Changed: false, Revision: cachedRevision}, nil
		}
	}

	res, err := g.backend.CloneOrSync(ctx, g.cfg, dest)
	if err != nil {
		return Result{}, err
	}

	if err := applyMode(ctx, dest, "", g.cfg.Owner, g.cfg.Group); err != nil {
		return Result{}, err
	}

	g.mu.Lock()
	if res.Revision != "" {
		g.revision = res.Revision
	}
	g.mu.Unlock()

	RecordDest(dest)
	return res, nil
}

// Wipe forwards to the shared implementation. Git checkouts live under
// the same managed-root / RecordDest authorisation as every other
// Source.
func (g *gitSource) Wipe(ctx context.Context, dest string) error {
	return wipeDest(ctx, dest)
}

// String — short URL+ref handle for log lines.
func (g *gitSource) String() string {
	return fmt.Sprintf("git %s @ %s [%s]", g.cfg.URL, g.cfg.Ref, g.cfg.Driver)
}

// gitRefAllowedRE constrains refs to a sane character set. The list is
// the same one go-git's reference parser accepts plus a defense-in-
// depth restriction against any shell metacharacter — refs flow into
// args of "git ls-remote / git fetch" if a future shell-out driver
// lands, and an injection there would be catastrophic.
var gitRefAllowedRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,250}$`)

func validateGitConfig(cfg *GitConfig) error {
	if err := validateGitURL(cfg.URL); err != nil {
		return err
	}
	if cfg.Ref == "" {
		cfg.Ref = "main"
	} else if !gitRefAllowedRE.MatchString(cfg.Ref) {
		return fmt.Errorf("%w: ref must match %s", ErrInvalidConfig, gitRefAllowedRE.String())
	}
	if cfg.Driver == "" {
		cfg.Driver = "go-git"
	}
	return nil
}

func validateGitURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%w: url is empty", ErrInvalidConfig)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q not supported (https only for v1)", ErrInvalidConfig, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: url must not include userinfo", ErrInvalidConfig)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: url has no host", ErrInvalidConfig)
	}
	return nil
}

// errGitFetchUnimplemented is the sentinel a stubbed VersionControlBackend
// returns until Slice 10 fills in go-git. Tests in Slice 9 don't hit
// Fetch, so this never surfaces in green-state runs.
var errGitFetchUnimplemented = errors.New("remote: git Fetch unimplemented (slice 10)")
