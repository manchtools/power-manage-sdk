package remote

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// goGitFixture builds a real bare repository inside a temp dir, seeds
// it with one or more commits on a named branch, and exposes the URL
// the backend should clone from. No network, no `git` binary on PATH:
// go-git's pure-Go bits handle the whole transport via the local-path
// "transport" (the URL is a file system path, which go-git treats as a
// loopback transport without any actual file:// scheme).
type goGitFixture struct {
	t       *testing.T
	bareDir string
	repo    *gogit.Repository
}

func newGoGitFixture(t *testing.T) *goGitFixture {
	t.Helper()
	dir := t.TempDir()
	bare := filepath.Join(dir, "source.git")
	repo, err := gogit.PlainInit(bare, true)
	if err != nil {
		t.Fatalf("PlainInit bare: %v", err)
	}
	return &goGitFixture{t: t, bareDir: bare, repo: repo}
}

// commit appends a commit on the named branch with a single file
// (name → body). Returns the resulting commit SHA so tests can
// drift-compare without re-resolving.
func (f *goGitFixture) commit(branch, fileName, fileBody, message string) string {
	f.t.Helper()
	// Stage the file into a fresh tree built on top of whatever the
	// branch currently points at.
	storer := f.repo.Storer
	var parents []plumbing.Hash
	if ref, err := f.repo.Reference(plumbing.NewBranchReferenceName(branch), false); err == nil {
		parents = []plumbing.Hash{ref.Hash()}
	}

	// Encode the file blob.
	blob := plumbing.MemoryObject{}
	blob.SetType(plumbing.BlobObject)
	w, err := blob.Writer()
	if err != nil {
		f.t.Fatalf("blob writer: %v", err)
	}
	if _, err := w.Write([]byte(fileBody)); err != nil {
		f.t.Fatalf("blob write: %v", err)
	}
	_ = w.Close()
	blobHash, err := storer.SetEncodedObject(&blob)
	if err != nil {
		f.t.Fatalf("set blob: %v", err)
	}

	// Tree containing just this one file.
	tree := &object.Tree{
		Entries: []object.TreeEntry{
			{Name: fileName, Mode: 0o100644, Hash: blobHash},
		},
	}
	treeObj := plumbing.MemoryObject{}
	treeObj.SetType(plumbing.TreeObject)
	if err := tree.Encode(&treeObj); err != nil {
		f.t.Fatalf("encode tree: %v", err)
	}
	treeHash, err := storer.SetEncodedObject(&treeObj)
	if err != nil {
		f.t.Fatalf("set tree: %v", err)
	}

	// Commit on top of the existing branch tip (if any).
	sig := object.Signature{Name: "tester", Email: "tester@example.test", When: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	commit := &object.Commit{
		Author:       sig,
		Committer:    sig,
		Message:      message,
		TreeHash:     treeHash,
		ParentHashes: parents,
	}
	commitObj := plumbing.MemoryObject{}
	commitObj.SetType(plumbing.CommitObject)
	if err := commit.Encode(&commitObj); err != nil {
		f.t.Fatalf("encode commit: %v", err)
	}
	commitHash, err := storer.SetEncodedObject(&commitObj)
	if err != nil {
		f.t.Fatalf("set commit: %v", err)
	}

	// Move the branch ref to the new commit.
	ref := plumbing.NewHashReference(plumbing.NewBranchReferenceName(branch), commitHash)
	if err := storer.SetReference(ref); err != nil {
		f.t.Fatalf("set ref: %v", err)
	}
	// Also point HEAD at the branch on the very first commit so a
	// clone has somewhere to land.
	if len(parents) == 0 {
		head := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName(branch))
		if err := storer.SetReference(head); err != nil {
			f.t.Fatalf("set HEAD: %v", err)
		}
	}
	return commitHash.String()
}

// url returns the value the backend should put in GitConfig.URL. The
// bare repo directory path is what go-git's local-transport accepts.
func (f *goGitFixture) url() string { return f.bareDir }

// TestGoGitBackend_FirstCloneCheckoutsRef — the smoke test. Backend
// clones the seeded repo into a temp dest at the named ref; the
// expected file lands with the expected body; the returned Result
// reports Changed=true and the SHA we just committed as Revision.
func TestGoGitBackend_FirstCloneCheckoutsRef(t *testing.T) {
	fix := newGoGitFixture(t)
	sha := fix.commit("main", "hello.txt", "world", "init")

	dest := filepath.Join(t.TempDir(), "co")
	recordDestUnder(t, dest)

	cfg := GitConfig{URL: fix.url(), Ref: "main", Driver: "go-git"}
	res, err := (goGitBackend{}).CloneOrSync(context.Background(), cfg, dest)
	if err != nil {
		t.Fatalf("CloneOrSync: %v", err)
	}
	if !res.Changed {
		t.Fatal("Changed=false on first clone")
	}
	if res.Revision != sha {
		t.Fatalf("Revision = %q; want %q", res.Revision, sha)
	}
	body, err := os.ReadFile(filepath.Join(dest, "hello.txt"))
	if err != nil {
		t.Fatalf("read checked-out file: %v", err)
	}
	if string(body) != "world" {
		t.Fatalf("file body = %q; want %q", body, "world")
	}
}

// TestGoGitBackend_SecondFetchIsNoOpWhenRefUnchanged — call
// CloneOrSync twice without changing upstream. The second call must
// report Changed=false and return the same Revision.
func TestGoGitBackend_SecondFetchIsNoOpWhenRefUnchanged(t *testing.T) {
	fix := newGoGitFixture(t)
	sha := fix.commit("main", "a.txt", "alpha", "init")

	dest := filepath.Join(t.TempDir(), "co")
	recordDestUnder(t, dest)
	cfg := GitConfig{URL: fix.url(), Ref: "main", Driver: "go-git"}

	if _, err := (goGitBackend{}).CloneOrSync(context.Background(), cfg, dest); err != nil {
		t.Fatalf("first CloneOrSync: %v", err)
	}
	res2, err := (goGitBackend{}).CloneOrSync(context.Background(), cfg, dest)
	if err != nil {
		t.Fatalf("second CloneOrSync: %v", err)
	}
	if res2.Changed {
		t.Fatal("second CloneOrSync: Changed=true; want false on unchanged upstream")
	}
	if res2.Revision != sha {
		t.Fatalf("second Revision = %q; want %q", res2.Revision, sha)
	}
}

// TestGoGitBackend_RefSwapReChecksOut — bump the upstream ref between
// calls; CloneOrSync must catch the new SHA and update dest.
func TestGoGitBackend_RefSwapReChecksOut(t *testing.T) {
	fix := newGoGitFixture(t)
	fix.commit("main", "v.txt", "v1", "first")
	dest := filepath.Join(t.TempDir(), "co")
	recordDestUnder(t, dest)

	cfg := GitConfig{URL: fix.url(), Ref: "main", Driver: "go-git"}
	if _, err := (goGitBackend{}).CloneOrSync(context.Background(), cfg, dest); err != nil {
		t.Fatalf("first CloneOrSync: %v", err)
	}

	sha2 := fix.commit("main", "v.txt", "v2", "second")
	res, err := (goGitBackend{}).CloneOrSync(context.Background(), cfg, dest)
	if err != nil {
		t.Fatalf("second CloneOrSync: %v", err)
	}
	if !res.Changed {
		t.Fatal("Changed=false after upstream advance")
	}
	if res.Revision != sha2 {
		t.Fatalf("Revision = %q; want %q", res.Revision, sha2)
	}
	body, _ := os.ReadFile(filepath.Join(dest, "v.txt"))
	if string(body) != "v2" {
		t.Fatalf("checked-out file = %q; want v2", body)
	}
}

// TestGoGitBackend_PruneRemovesUntrackedFiles — when Prune=true, a
// local-only file left in dest from a previous tweak is cleaned up
// during sync. When Prune=false, it stays.
func TestGoGitBackend_PruneRemovesUntrackedFiles(t *testing.T) {
	for _, prune := range []bool{false, true} {
		t.Run(map[bool]string{true: "Prune=true", false: "Prune=false"}[prune], func(t *testing.T) {
			fix := newGoGitFixture(t)
			fix.commit("main", "tracked.txt", "x", "init")

			dest := filepath.Join(t.TempDir(), "co")
			recordDestUnder(t, dest)
			cfg := GitConfig{URL: fix.url(), Ref: "main", Driver: "go-git", Prune: prune}
			if _, err := (goGitBackend{}).CloneOrSync(context.Background(), cfg, dest); err != nil {
				t.Fatalf("CloneOrSync: %v", err)
			}

			extra := filepath.Join(dest, "untracked.txt")
			if err := os.WriteFile(extra, []byte("local"), 0o600); err != nil {
				t.Fatalf("write extra: %v", err)
			}

			// Bump upstream to force a re-sync.
			fix.commit("main", "tracked.txt", "y", "second")
			if _, err := (goGitBackend{}).CloneOrSync(context.Background(), cfg, dest); err != nil {
				t.Fatalf("second CloneOrSync: %v", err)
			}
			_, statErr := os.Stat(extra)
			if prune && !os.IsNotExist(statErr) {
				t.Fatalf("Prune=true but extra file survived: stat err = %v", statErr)
			}
			if !prune && statErr != nil {
				t.Fatalf("Prune=false but extra file gone: stat err = %v", statErr)
			}
		})
	}
}

// TestGoGitBackend_Resolve_ReturnsUpstreamSha — Resolve must reach the
// upstream without touching dest. Returned SHA must match the
// fixture's most recent commit hash on the named branch.
func TestGoGitBackend_Resolve_ReturnsUpstreamSha(t *testing.T) {
	fix := newGoGitFixture(t)
	sha := fix.commit("main", "a", "b", "init")
	cfg := GitConfig{URL: fix.url(), Ref: "main", Driver: "go-git"}

	got, err := (goGitBackend{}).Resolve(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != sha {
		t.Fatalf("Resolve = %q; want %q", got, sha)
	}
}

// TestGoGitBackend_TagRef_ChecksOutTag — cfg.Ref may be a tag, not
// just a branch name. The clone path must reach the tag's commit
// (regression test for the CodeRabbit critical: openOrClone used to
// hard-code refs/heads/<ref> which failed for tags and SHAs).
func TestGoGitBackend_TagRef_ChecksOutTag(t *testing.T) {
	fix := newGoGitFixture(t)
	sha := fix.commit("main", "x.txt", "tagged", "init")

	// Lay down a lightweight tag pointing at the just-committed SHA.
	tagRef := plumbing.NewHashReference(plumbing.NewTagReferenceName("v1.0.0"), plumbing.NewHash(sha))
	if err := fix.repo.Storer.SetReference(tagRef); err != nil {
		t.Fatalf("set tag ref: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "co")
	recordDestUnder(t, dest)
	cfg := GitConfig{URL: fix.url(), Ref: "v1.0.0", Driver: "go-git"}
	res, err := (goGitBackend{}).CloneOrSync(context.Background(), cfg, dest)
	if err != nil {
		t.Fatalf("CloneOrSync(tag): %v", err)
	}
	if res.Revision != sha {
		t.Fatalf("Revision = %q; want %q", res.Revision, sha)
	}
	body, err := os.ReadFile(filepath.Join(dest, "x.txt"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "tagged" {
		t.Fatalf("file body = %q; want %q", body, "tagged")
	}
}

// TestGoGitBackend_BadRef_ReturnsError — a ref that doesn't exist
// upstream returns a non-nil error and leaves dest absent.
func TestGoGitBackend_BadRef_ReturnsError(t *testing.T) {
	fix := newGoGitFixture(t)
	fix.commit("main", "x", "y", "init")
	dest := filepath.Join(t.TempDir(), "co")
	recordDestUnder(t, dest)
	cfg := GitConfig{URL: fix.url(), Ref: "nope-not-a-real-ref", Driver: "go-git"}
	_, err := (goGitBackend{}).CloneOrSync(context.Background(), cfg, dest)
	if err == nil {
		t.Fatal("CloneOrSync with bad ref returned nil")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("dest should not exist after bad-ref failure: %v", statErr)
	}
}

// TestGitSource_FetchEndToEnd — drives the public Source.Fetch surface
// (NewGit + the real go-git backend) end-to-end. Lets the integration
// between gitSource and the backend stay green even if the unit-level
// backend tests get refactored.
func TestGitSource_FetchEndToEnd(t *testing.T) {
	fix := newGoGitFixture(t)
	sha := fix.commit("main", "readme.md", "# hi", "init")
	dest := filepath.Join(t.TempDir(), "co")
	recordDestUnder(t, dest)

	src, err := newGitSourceForTest(GitConfig{URL: fix.url(), Ref: "main"})
	if err != nil {
		t.Fatalf("newGitSourceForTest: %v", err)
	}

	res, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Revision != sha {
		t.Fatalf("Fetch Revision = %q; want %q", res.Revision, sha)
	}

	// Second call short-circuits without re-cloning.
	res2, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if res2.Changed {
		t.Fatal("second Fetch Changed=true")
	}
}

// newGitSourceForTest builds a gitSource that bypasses NewGit's URL
// validation (which would reject the local file-system path the
// fixture uses). The end-to-end test wants the gitSource code path
// without forcing the test to spin up an HTTPS server with TLS certs.
func newGitSourceForTest(cfg GitConfig) (Source, error) {
	if cfg.Ref == "" {
		cfg.Ref = "main"
	}
	if cfg.Driver == "" {
		cfg.Driver = "go-git"
	}
	backend, err := versionControlBackend(cfg.Driver)
	if err != nil {
		return nil, err
	}
	return &gitSource{cfg: cfg, backend: backend}, nil
}
