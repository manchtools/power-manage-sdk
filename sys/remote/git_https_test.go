package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// TestGitFetch_RealHTTPS exercises the go-git clone + re-sync path against a REAL
// git repository served over the smart-HTTP protocol by git-http-backend over
// TLS — the path NewGit requires (https only) that no in-process fixture could
// reach. Covers CloneOrSync / openOrClone (both the clone and the reopen
// branches) and Resolve's success path.
//
// Self-skips when git or git-http-backend is unavailable; the test-go-all CI
// host (ubuntu) ships both, so the path is covered there.
func TestGitFetch_RealHTTPS(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not present")
	}
	backend := gitHTTPBackend(t)
	if backend == "" {
		t.Skip("git-http-backend not present")
	}

	root := t.TempDir()
	// A working repo with one commit on 'main', cloned to a bare repo to serve.
	work := filepath.Join(root, "work")
	runGit(t, "", "init", "-q", "-b", "main", work)
	runGit(t, work, "config", "user.email", "t@e")
	runGit(t, work, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(work, "f"), []byte("hello-https"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "f")
	runGit(t, work, "-c", "commit.gpgsign=false", "commit", "-qm", "init")
	runGit(t, "", "clone", "-q", "--bare", work, filepath.Join(root, "repo.git"))

	// Serve every repo under root via git-http-backend (smart HTTP) over TLS.
	srv := httptest.NewTLSServer(&cgi.Handler{
		Path: backend,
		Dir:  root,
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	})
	defer srv.Close()

	// Make go-git trust the httptest TLS cert for the duration of the test.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	trusting := githttp.NewClient(&http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	})
	client.InstallProtocol("https", trusting)
	defer client.InstallProtocol("https", githttp.DefaultClient)

	src, err := NewGit(GitConfig{URL: srv.URL + "/repo.git", Ref: "main"})
	if err != nil {
		t.Fatalf("NewGit: %v", err)
	}
	ctx := context.Background()
	dest := filepath.Join(t.TempDir(), "checkout")

	// First Fetch → clone.
	if _, err := src.Fetch(ctx, dest); err != nil {
		t.Fatalf("Fetch (clone): %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "f")); string(b) != "hello-https" {
		t.Errorf("cloned file content = %q, want hello-https", b)
	}

	// Second Fetch into the same dest → reopen the existing repo + re-sync (no
	// clone): exercises openOrClone's reopen branch.
	if _, err := src.Fetch(ctx, dest); err != nil {
		t.Fatalf("Fetch (re-sync): %v", err)
	}
}

func gitHTTPBackend(t *testing.T) string {
	t.Helper()
	out, err := osexec.Command("git", "--exec-path").Output()
	if err != nil {
		return ""
	}
	candidate := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(candidate); err != nil {
		return ""
	}
	return candidate
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := osexec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}
