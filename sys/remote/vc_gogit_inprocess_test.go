package remote

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// initRepoWithCommit creates a real git repo at dir with one committed file and
// returns the repo, its worktree, and the commit hash. Pure in-process go-git —
// no network, no git binary.
func initRepoWithCommit(t *testing.T, dir string) (*gogit.Repository, *gogit.Worktree, plumbing.Hash) {
	t.Helper()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tracked"), []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("tracked"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	h, err := wt.Commit("init", &gogit.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@e", When: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return repo, wt, h
}

func TestResolveTargetHash(t *testing.T) {
	dir := t.TempDir()
	repo, _, h := initRepoWithCommit(t, dir)

	branch, err := repo.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if _, err := repo.CreateTag("v1", h, nil); err != nil {
		t.Fatalf("CreateTag: %v", err)
	}

	// Branch name (refs/heads/<branch>).
	if got, err := resolveTargetHash(repo, branch.Name().Short()); err != nil || got != h {
		t.Errorf("resolveTargetHash(branch) = (%v,%v), want (%v,nil)", got, err, h)
	}
	// Tag name (refs/tags/v1).
	if got, err := resolveTargetHash(repo, "v1"); err != nil || got != h {
		t.Errorf("resolveTargetHash(tag) = (%v,%v), want (%v,nil)", got, err, h)
	}
	// Raw SHA fallback.
	if got, err := resolveTargetHash(repo, h.String()); err != nil || got != h {
		t.Errorf("resolveTargetHash(sha) = (%v,%v), want (%v,nil)", got, err, h)
	}
	// Not found → ErrInvalidConfig.
	if _, err := resolveTargetHash(repo, "no-such-ref"); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("resolveTargetHash(missing) err = %v, want ErrInvalidConfig", err)
	}
}

func TestSnapshotRestoreUntracked(t *testing.T) {
	dir := t.TempDir()
	_, wt, _ := initRepoWithCommit(t, dir)

	// Two untracked files (one nested).
	if err := os.WriteFile(filepath.Join(dir, "u1"), []byte("keep1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "u2"), []byte("keep2"), 0o600); err != nil {
		t.Fatal(err)
	}

	snap, err := snapshotUntracked(dir, wt)
	if err != nil {
		t.Fatalf("snapshotUntracked: %v", err)
	}
	if len(snap) < 2 {
		t.Fatalf("snapshot captured %d untracked files, want >= 2", len(snap))
	}

	// Simulate a checkout blowing them away, then restore.
	_ = os.Remove(filepath.Join(dir, "u1"))
	_ = os.RemoveAll(filepath.Join(dir, "sub"))
	if err := restoreUntracked(dir, snap); err != nil {
		t.Fatalf("restoreUntracked: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "u1")); string(b) != "keep1" {
		t.Errorf("u1 not restored: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "sub", "u2")); string(b) != "keep2" {
		t.Errorf("sub/u2 not restored: %q", b)
	}
}

// TestResolve_LsRemoteError covers the Resolve error path: an unreachable
// endpoint makes the in-memory ls-remote fail. (The success path needs a live
// git remote — covered by the container/integration tier, not here.)
func TestResolve_LsRemoteError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := goGitBackend{}.Resolve(ctx, GitConfig{URL: "https://127.0.0.1:1/nope.git", Ref: "main"})
	if err == nil {
		t.Error("Resolve against an unreachable endpoint returned nil error")
	}
}
