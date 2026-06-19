package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// httpFixture wires up an httptest.Server that serves payload bytes with
// the supplied ETag, and counts incoming GET vs HEAD requests so tests
// can assert "second call did not re-download". The fixture is the
// per-test environment for every Slice-4 case.
type httpFixture struct {
	srv      *httptest.Server
	payload  []byte
	etag     string
	gets     atomic.Int32
	heads    atomic.Int32
	getDelay func(io.Writer) // optional per-GET hook for size-cap tests
}

func newHTTPFixture(t *testing.T, payload []byte, etag string) *httpFixture {
	t.Helper()
	f := &httpFixture{payload: payload, etag: etag}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", f.etag)
		switch r.Method {
		case http.MethodHead:
			f.heads.Add(1)
			if r.Header.Get("If-None-Match") == f.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			f.gets.Add(1)
			if r.Header.Get("If-None-Match") == f.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.WriteHeader(http.StatusOK)
			if f.getDelay != nil {
				f.getDelay(w)
				return
			}
			_, _ = w.Write(f.payload)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// recordDestUnder is the per-test helper that lets canWipe / canFetch
// accept paths under the test's temp dir. Same mechanism a real Fetch
// uses when it succeeds, but invoked manually here so the test doesn't
// have to land a green Slice-6 first.
func recordDestUnder(t *testing.T, dest string) {
	t.Helper()
	RecordDest(dest)
	t.Cleanup(func() { forgetDest(dest) })
}

// TestHTTPFetch_DownloadsToDest — the smoke test for the GET path.
// Asserts the payload landed at dest verbatim and the Result carries
// the basic accounting we'll need downstream (Changed, BytesWritten,
// FilesTouched=1, Digest, Revision).
func TestHTTPFetch_DownloadsToDest(t *testing.T) {
	payload := []byte("alpha bravo charlie")
	fix := newHTTPFixture(t, payload, `"v1"`)
	dest := filepath.Join(t.TempDir(), "file")
	recordDestUnder(t, dest)

	src, err := NewHTTP(HTTPConfig{URL: fix.srv.URL + "/file"})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	res, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if !res.Changed {
		t.Fatal("Result.Changed=false on first call")
	}
	if res.BytesWritten != int64(len(payload)) {
		t.Fatalf("BytesWritten = %d; want %d", res.BytesWritten, len(payload))
	}
	if res.FilesTouched != 1 {
		t.Fatalf("FilesTouched = %d; want 1", res.FilesTouched)
	}
	wantSum := sha256.Sum256(payload)
	if res.Digest != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("Digest = %q; want %q", res.Digest, hex.EncodeToString(wantSum[:]))
	}
	if res.Revision == "" {
		t.Fatal("Revision empty; want non-empty drift token")
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("dest content = %q; want %q", got, payload)
	}
}

// TestHTTPFetch_AtomicWrite_LeavesNoTmpBehind — the on-disk surface
// during a fetch should never expose a partial file. Verified by
// scanning the destination's parent directory for any `<base>.tmp.*`
// siblings after a successful Fetch.
func TestHTTPFetch_AtomicWrite_LeavesNoTmpBehind(t *testing.T) {
	payload := []byte("zigzag")
	fix := newHTTPFixture(t, payload, `"v1"`)
	dir := t.TempDir()
	dest := filepath.Join(dir, "file")
	recordDestUnder(t, dest)

	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + "/file"})
	if _, err := src.Fetch(context.Background(), dest); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "file.tmp.") {
			t.Fatalf("leftover tmp file: %s", e.Name())
		}
	}
}

// TestHTTPFetch_ChecksumMismatch — the integrity guarantee. If the
// caller pinned a sha256 and the server returns something else, Fetch
// must return ErrIntegrity and leave dest untouched.
func TestHTTPFetch_ChecksumMismatch(t *testing.T) {
	fix := newHTTPFixture(t, []byte("real body"), `"v1"`)
	dir := t.TempDir()
	dest := filepath.Join(dir, "file")
	recordDestUnder(t, dest)

	src, err := NewHTTP(HTTPConfig{
		URL:            fix.srv.URL + "/file",
		ChecksumSHA256: strings.Repeat("0", 64), // sha256 of nothing real
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if _, err := src.Fetch(context.Background(), dest); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Fetch err = %v; want errors.Is(..., ErrIntegrity)", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("dest should not exist after checksum failure; stat err = %v", err)
	}
}

// TestHTTPFetch_RespectsMaxBytes — the size cap. If the body exceeds
// MaxBytes the fetch aborts with ErrIntegrity (treating an oversize
// payload as a tamper / misconfiguration signal, same bucket as a bad
// checksum). dest must not exist after.
func TestHTTPFetch_RespectsMaxBytes(t *testing.T) {
	fix := newHTTPFixture(t, nil, `"v1"`)
	fix.getDelay = func(w io.Writer) {
		// Stream 10 KiB while the test caps at 1 KiB.
		buf := make([]byte, 1024)
		for i := 0; i < 10; i++ {
			_, _ = w.Write(buf)
		}
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "file")
	recordDestUnder(t, dest)

	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + "/file", MaxBytes: 1024})
	if _, err := src.Fetch(context.Background(), dest); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Fetch err = %v; want errors.Is(..., ErrIntegrity) for size-cap breach", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("dest should not exist after size-cap failure; stat err = %v", err)
	}
}

// TestHTTPFetch_SecondCallNoOp_WhenETagMatches — drift detection. A
// fresh Source instance fetched twice in succession against an
// unchanged origin should HEAD-probe the second time and skip the
// GET entirely.
func TestHTTPFetch_SecondCallNoOp_WhenETagMatches(t *testing.T) {
	fix := newHTTPFixture(t, []byte("body"), `"v1"`)
	dir := t.TempDir()
	dest := filepath.Join(dir, "file")
	recordDestUnder(t, dest)

	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + "/file"})

	res1, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("Fetch #1: %v", err)
	}
	if !res1.Changed {
		t.Fatal("first Fetch: Changed=false")
	}
	gets1 := fix.gets.Load()

	res2, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("Fetch #2: %v", err)
	}
	if res2.Changed {
		t.Fatal("second Fetch with unchanged ETag: Changed=true")
	}
	if res2.Revision != res1.Revision {
		t.Fatalf("Revision changed between no-op fetches: %q vs %q", res1.Revision, res2.Revision)
	}
	if got := fix.gets.Load(); got != gets1 {
		t.Fatalf("second Fetch issued a GET (count went %d → %d)", gets1, got)
	}
}

// TestHTTPFetch_AppliesMode — when cfg.Mode is set, the resulting file
// must end up with those permission bits. Ownership is not tested here
// because chown requires root; that branch is integration-tested.
func TestHTTPFetch_AppliesMode(t *testing.T) {
	fix := newHTTPFixture(t, []byte("data"), `"v1"`)
	dir := t.TempDir()
	dest := filepath.Join(dir, "file")
	recordDestUnder(t, dest)

	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + "/file", Mode: "0640"})
	if _, err := src.Fetch(context.Background(), dest); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("mode = %v; want 0640", got)
	}
}

// TestHTTPFetch_RejectsUnsafeDest — dest validation is mandatory even
// when the rest of the config is fine. A non-absolute path must fail
// before any network traffic.
func TestHTTPFetch_RejectsUnsafeDest(t *testing.T) {
	fix := newHTTPFixture(t, []byte("x"), `"v1"`)
	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + "/file"})
	if _, err := src.Fetch(context.Background(), "relative/path"); !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("Fetch err = %v; want errors.Is(..., ErrUnsafeDestination)", err)
	}
	if got := fix.gets.Load() + fix.heads.Load(); got != 0 {
		t.Fatalf("network was hit %d times before dest validation", got)
	}
}
