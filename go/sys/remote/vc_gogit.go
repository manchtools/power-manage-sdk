package remote

import (
	"context"
)

// goGitBackend is the v1 default version-control driver. Backed by
// github.com/go-git/go-git/v5 in Slice 10; Slice 9 just registers a
// stub under the canonical "go-git" name so NewGit's default-driver
// path can resolve.
type goGitBackend struct{}

func (goGitBackend) CloneOrSync(_ context.Context, _ GitConfig, _ string) (Result, error) {
	return Result{}, errGitFetchUnimplemented
}

func (goGitBackend) Resolve(_ context.Context, _ GitConfig) (string, error) {
	return "", errGitFetchUnimplemented
}

func init() {
	RegisterVersionControlBackend("go-git", goGitBackend{})
}
