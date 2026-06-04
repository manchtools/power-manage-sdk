package remote

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage/memory"
)

// goGitBackend is the v1 default version-control driver. Implements
// VersionControlBackend against github.com/go-git/go-git/v5, in-process
// — no external `git` binary required.
//
// The "URL" go-git accepts is generous: any filesystem path or
// https://, ssh://, git://, file:// URL. NewGit's validation already
// narrows public callers to https://; the backend itself trusts the
// caller-provided URL (this is what makes the hermetic tests work
// with a temp-dir bare repo).
type goGitBackend struct{}

func init() {
	RegisterVersionControlBackend("go-git", goGitBackend{})
}

// CloneOrSync brings the repo at cfg.URL to dest, checked out at the
// configured ref. On a fresh dest it clones from scratch; on a
// re-existing dest it fetches the latest refs and checks out the
// target.
//
// cfg.Ref can be a branch, tag, or full commit SHA. The clone path
// deliberately does NOT pre-pin a ReferenceName: that would lock the
// clone to refs/heads/<ref>, which fails for tags and SHAs. Instead
// the clone fetches every ref (including tags), then resolveTargetHash
// converts cfg.Ref to a plumbing.Hash post-clone — the only path that
// handles all three ref shapes uniformly.
//
// Result.Revision is the commit SHA dest points at after the operation;
// Result.Changed is true on the first clone and on any sync that
// advanced HEAD, false when the previously checked-out commit already
// matches upstream.
func (goGitBackend) CloneOrSync(ctx context.Context, cfg GitConfig, dest string) (Result, error) {
	repo, fresh, err := openOrClone(ctx, cfg, dest)
	if err != nil {
		return Result{}, err
	}

	if !fresh {
		if err := goGitFetch(ctx, repo); err != nil && !errors.Is(err, gogit.NoErrAlreadyUpToDate) {
			return Result{}, fmt.Errorf("fetch %s: %w", cfg.URL, err)
		}
	}

	target, err := resolveTargetHash(repo, cfg.Ref)
	if err != nil {
		// On a fresh clone, an unresolvable ref means the operator
		// pointed us at a non-existent branch/tag/SHA. Nuke dest so
		// the next cycle starts clean and doesn't leave a half-
		// configured repo behind.
		if fresh {
			_ = os.RemoveAll(dest)
		}
		return Result{}, err
	}

	prevHead, headErr := repo.Head()
	if !fresh && headErr == nil && prevHead.Hash() == target {
		// Already at the right commit — Fetch may still have written
		// pack files into .git, but the worktree is unchanged. Optional
		// prune still runs so a previous "I leaked an untracked file"
		// gets cleaned up on the next cycle when Prune=true.
		if cfg.Prune {
			wt, werr := repo.Worktree()
			if werr == nil {
				_ = wt.Clean(&gogit.CleanOptions{Dir: true})
			}
		}
		return Result{Changed: false, Revision: target.String()}, nil
	}

	wt, err := repo.Worktree()
	if err != nil {
		return Result{}, fmt.Errorf("worktree: %w", err)
	}

	// go-git's Checkout(Force=true) removes files that aren't in the
	// target tree, including untracked ones. That conflicts with the
	// Prune=false contract ("additive sync, preserve local additions"),
	// so we snapshot untracked files first and restore them after the
	// checkout. Fresh clones have nothing to snapshot; Prune=true
	// skips the snapshot — Clean drops them below anyway.
	var snapshot []untrackedFile
	if !fresh && !cfg.Prune {
		snapshot, _ = snapshotUntracked(dest, wt)
	}

	if err := wt.Checkout(&gogit.CheckoutOptions{Hash: target, Force: true}); err != nil {
		if fresh {
			_ = os.RemoveAll(dest)
		}
		return Result{}, fmt.Errorf("checkout %s: %w", target, err)
	}

	if len(snapshot) > 0 {
		if err := restoreUntracked(dest, snapshot); err != nil {
			return Result{}, fmt.Errorf("restore untracked: %w", err)
		}
	}

	if cfg.Prune {
		if err := wt.Clean(&gogit.CleanOptions{Dir: true}); err != nil {
			return Result{}, fmt.Errorf("clean: %w", err)
		}
	}

	// Count regular files in the working tree for FilesTouched — same
	// shape as the HTTP archive branch. Cheap walk; only runs when
	// Changed=true.
	files, total, _ := countTreeFiles(dest)

	return Result{
		Changed:      true,
		BytesWritten: total,
		FilesTouched: files,
		Revision:     target.String(),
	}, nil
}

// Resolve returns the upstream SHA the configured ref points at, without
// touching dest. Uses an in-memory storer so the call has no on-disk
// side effects — same pattern as `git ls-remote`.
func (goGitBackend) Resolve(ctx context.Context, cfg GitConfig) (string, error) {
	rem := gogit.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{cfg.URL},
	})
	refs, err := rem.ListContext(ctx, &gogit.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("ls-remote %s: %w", cfg.URL, err)
	}
	hash, ok := matchRef(refs, cfg.Ref)
	if !ok {
		return "", fmt.Errorf("%w: ref %q not found at %s", ErrInvalidConfig, cfg.Ref, cfg.URL)
	}
	return hash.String(), nil
}

// openOrClone returns a *Repository for dest, cloning from cfg.URL
// if dest doesn't already host a checkout. The fresh return is true
// when a clone happened (caller treats Changed as unconditionally
// true), false when the existing repo was reopened (caller compares
// pre / post HEAD).
func openOrClone(ctx context.Context, cfg GitConfig, dest string) (*gogit.Repository, bool, error) {
	if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
		repo, oerr := gogit.PlainOpen(dest)
		if oerr != nil {
			return nil, false, fmt.Errorf("open existing %s: %w", dest, oerr)
		}
		return repo, false, nil
	}
	// Fresh clone — make sure the parent exists; go-git creates dest
	// itself but won't mkdir-p the chain above it.
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return nil, false, fmt.Errorf("mkdir parent of %s: %w", dest, err)
	}
	// Deliberately no ReferenceName / SingleBranch: those would lock
	// the clone to refs/heads/<ref>, which fails for tag and SHA
	// refs. Fetching everything (Tags: AllTags) makes
	// resolveTargetHash robust regardless of cfg.Ref's shape.
	opts := &gogit.CloneOptions{
		URL:               cfg.URL,
		Tags:              gogit.AllTags,
		RecurseSubmodules: gogit.NoRecurseSubmodules,
	}
	if cfg.Submodules {
		opts.RecurseSubmodules = gogit.DefaultSubmoduleRecursionDepth
	}
	repo, err := gogit.PlainCloneContext(ctx, dest, false, opts)
	if err != nil {
		// On clone failure leave nothing partial behind. PlainClone
		// sometimes creates dest before failing; rm-rf is correct here
		// (Result hasn't committed to "dest exists" yet).
		_ = os.RemoveAll(dest)
		return nil, false, fmt.Errorf("clone %s: %w", cfg.URL, err)
	}
	return repo, true, nil
}

// goGitFetch fetches refs from origin into the existing repo's object
// store. No checkout — that's the caller's responsibility once it
// picks the target hash. Two explicit RefSpecs cover both branches
// and tags, since the clone path doesn't pre-pin ReferenceName
// (necessary to accept tag/SHA refs uniformly); resolveTargetHash
// looks under refs/remotes/origin/* and refs/tags/* afterwards.
func goGitFetch(ctx context.Context, repo *gogit.Repository) error {
	return repo.FetchContext(ctx, &gogit.FetchOptions{
		RemoteName: "origin",
		RefSpecs: []config.RefSpec{
			"+refs/heads/*:refs/remotes/origin/*",
			"+refs/tags/*:refs/tags/*",
		},
		Tags:  gogit.AllTags,
		Force: true,
	})
}

// resolveTargetHash maps the user-provided ref (branch / tag / SHA) to
// a concrete plumbing.Hash inside the repo. Tries branches first, then
// tags, then a raw SHA parse — matches `git checkout <ref>` semantics.
func resolveTargetHash(repo *gogit.Repository, ref string) (plumbing.Hash, error) {
	// Branch ref (origin/<ref> after a fetch, or refs/heads/<ref> on a
	// fresh single-branch clone where origin sent us straight to a
	// branch under .git/refs/heads).
	for _, candidate := range []string{
		"refs/remotes/origin/" + ref,
		"refs/heads/" + ref,
		"refs/tags/" + ref,
	} {
		if r, err := repo.Reference(plumbing.ReferenceName(candidate), true); err == nil {
			return r.Hash(), nil
		}
	}
	// Raw SHA fallback.
	if h := plumbing.NewHash(ref); !h.IsZero() {
		if _, err := repo.CommitObject(h); err == nil {
			return h, nil
		}
	}
	return plumbing.ZeroHash, fmt.Errorf("%w: ref %q not found", ErrInvalidConfig, ref)
}

// matchRef picks the upstream reference matching ref from a ls-remote
// result. Tries refs/heads/<ref>, refs/tags/<ref>, and HEAD-symbolic
// in that order.
func matchRef(refs []*plumbing.Reference, ref string) (plumbing.Hash, bool) {
	for _, r := range refs {
		switch r.Name().String() {
		case "refs/heads/" + ref, "refs/tags/" + ref:
			return r.Hash(), true
		}
	}
	// Annotated tags appear as refs/tags/<name>^{}; if a caller asked
	// for the bare tag name, also try the dereferenced form by
	// matching the prefix (uncommon but valid).
	for _, r := range refs {
		if r.Name().String() == "refs/tags/"+ref+"^{}" {
			return r.Hash(), true
		}
	}
	return plumbing.ZeroHash, false
}

// countTreeFiles walks dest, skipping the .git directory, and returns
// (file count, total bytes, walkErr). Best-effort; errors fall back to
// zero values so a successful clone still returns a sensible Result.
func countTreeFiles(dest string) (int, int64, error) {
	var files int
	var total int64
	err := filepath.WalkDir(dest, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" && path != dest {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			files++
			info, ierr := d.Info()
			if ierr == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return files, total, err
}

// untrackedFile is the snapshot record for a single non-.git,
// non-tracked file under dest. Path is relative to dest so a
// post-checkout restore can re-join it cleanly.
type untrackedFile struct {
	relPath string
	body    []byte
	mode    os.FileMode
}

// snapshotUntracked walks dest (skipping .git) and records every
// regular file that go-git's worktree.Status reports as Untracked.
// Returns the slice + any walk error (callers downgrade walk errors
// to a best-effort log; the worst case is a few untracked files
// disappearing on a sync, which is recoverable).
func snapshotUntracked(dest string, wt *gogit.Worktree) ([]untrackedFile, error) {
	st, err := wt.Status()
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	var out []untrackedFile
	for relPath, entry := range st {
		if entry.Worktree != gogit.Untracked {
			continue
		}
		full := filepath.Join(dest, relPath)
		info, ierr := os.Lstat(full)
		if ierr != nil {
			continue // raced / not a regular file
		}
		if !info.Mode().IsRegular() {
			continue
		}
		body, rerr := os.ReadFile(full) //nolint:gosec // path constructed from dest + status output.
		if rerr != nil {
			continue
		}
		out = append(out, untrackedFile{
			relPath: relPath,
			body:    body,
			mode:    info.Mode().Perm(),
		})
	}
	return out, nil
}

// restoreUntracked writes each snapshot entry back under dest. Creates
// intermediate directories as needed; mirrors the mode bits captured
// at snapshot time.
func restoreUntracked(dest string, snap []untrackedFile) error {
	for _, f := range snap {
		full := filepath.Join(dest, f.relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, f.body, f.mode); err != nil {
			return fmt.Errorf("write %s: %w", full, err)
		}
	}
	return nil
}

var _ = storer.ErrStop // anchor the storer import for future use (HEAD walk in v2)
