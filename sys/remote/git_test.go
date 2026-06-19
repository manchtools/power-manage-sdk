package remote

import (
	"errors"
	"strings"
	"testing"
)

// TestNewGit_AcceptsValidConfig — minimal valid config returns a
// non-nil Source whose String() identifies the URL+ref so log lines
// stay useful.
func TestNewGit_AcceptsValidConfig(t *testing.T) {
	src, err := NewGit(GitConfig{URL: "https://example.test/repo.git", Ref: "main"})
	if err != nil {
		t.Fatalf("NewGit: %v", err)
	}
	if src == nil {
		t.Fatal("NewGit returned nil Source")
	}
	if got := src.String(); !strings.Contains(got, "example.test") || !strings.Contains(got, "main") {
		t.Fatalf("Source.String() = %q; want URL+ref content", got)
	}
}

// TestNewGit_RejectsBadURL — only https:// supported in v1. Everything
// else (ssh, git, file, http, missing scheme) gets rejected up front.
// http (no TLS) is deliberately rejected too: an in-flight tamper of
// the clone is exactly the scenario this primitive must defend against.
func TestNewGit_RejectsBadURL(t *testing.T) {
	for _, c := range []string{
		"",
		"   ",
		"github.com/foo/bar", // no scheme
		"http://example.test/repo.git",
		"ssh://git@example.test/repo.git",
		"git://example.test/repo.git",
		"file:///srv/repo.git",
		"https://user:pass@example.test/repo.git",
	} {
		t.Run("url="+c, func(t *testing.T) {
			_, err := NewGit(GitConfig{URL: c})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewGit(%q) = %v; want ErrInvalidConfig", c, err)
			}
		})
	}
}

// TestNewGit_RejectsBadRef — refs feed into go-git which is reasonably
// strict, but defense-in-depth: reject anything that's plausibly an
// injection vector (whitespace, shell metacharacters, > 250 chars).
func TestNewGit_RejectsBadRef(t *testing.T) {
	for _, ref := range []string{
		"refs with space",
		"; rm -rf /",
		"$(touch /tmp/x)",
		"`whoami`",
		"ref|other",
		strings.Repeat("a", 251),
	} {
		t.Run("ref="+ref[:min(len(ref), 16)], func(t *testing.T) {
			_, err := NewGit(GitConfig{
				URL: "https://example.test/repo.git",
				Ref: ref,
			})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewGit(ref=%q) = %v; want ErrInvalidConfig", ref, err)
			}
		})
	}
}

// TestNewGit_DefaultsRefToMain — an empty Ref normalises to "main" so
// the caller can rely on a non-empty value downstream.
func TestNewGit_DefaultsRefToMain(t *testing.T) {
	src, err := NewGit(GitConfig{URL: "https://example.test/repo.git"})
	if err != nil {
		t.Fatalf("NewGit: %v", err)
	}
	gs := src.(*gitSource)
	if gs.cfg.Ref != "main" {
		t.Fatalf("default ref = %q; want main", gs.cfg.Ref)
	}
}

// TestNewGit_DefaultDriverIsGoGit — empty Driver resolves to the
// registered "go-git" backend. Locks the default contract — operators
// don't have to know about driver selection unless they want to.
func TestNewGit_DefaultDriverIsGoGit(t *testing.T) {
	src, err := NewGit(GitConfig{URL: "https://example.test/repo.git"})
	if err != nil {
		t.Fatalf("NewGit: %v", err)
	}
	gs := src.(*gitSource)
	if gs.cfg.Driver != "go-git" {
		t.Fatalf("default driver = %q; want go-git", gs.cfg.Driver)
	}
	if gs.backend == nil {
		t.Fatal("gitSource.backend nil; default driver wasn't resolved")
	}
}

// TestNewGit_UnknownDriver — choosing a driver that nobody registered
// fails at construction time, not at the first Fetch.
func TestNewGit_UnknownDriver(t *testing.T) {
	_, err := NewGit(GitConfig{
		URL:    "https://example.test/repo.git",
		Driver: "no-such-driver",
	})
	if !errors.Is(err, ErrBackendNotFound) {
		t.Fatalf("NewGit(unknown driver) = %v; want ErrBackendNotFound", err)
	}
}
