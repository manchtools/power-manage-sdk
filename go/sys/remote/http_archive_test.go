package remote

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// archiveFixture is the per-test rig for Slice 5: an httptest server
// that serves a caller-supplied body with a caller-supplied
// Content-Type, and a URL path used for filename-extension hints.
type archiveFixture struct {
	srv         *httptest.Server
	body        []byte
	contentType string
	urlPath     string
	etag        string
}

func newArchiveFixture(t *testing.T, body []byte, contentType, urlPath, etag string) *archiveFixture {
	t.Helper()
	if urlPath == "" {
		urlPath = "/archive"
	}
	a := &archiveFixture{body: body, contentType: contentType, urlPath: urlPath, etag: etag}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", a.etag)
		if a.contentType != "" {
			w.Header().Set("Content-Type", a.contentType)
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(a.body)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// buildTarGz packs the given files into a gzipped tar stream. Files'
// `name` is the entry path; an empty body field means "directory entry".
// Symlinks are emitted when `linkname` is non-empty.
func buildTarGz(t *testing.T, files []archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range files {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body))}
		switch {
		case e.linkname != "":
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.linkname
			hdr.Size = 0
		case e.isDir:
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0o755
			hdr.Size = 0
		default:
			hdr.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("tar body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}

// buildZip packs files into a zip stream. linkname is unsupported here;
// zip's symlink representation differs and we don't accept it anyway
// (the safety layer rejects all symlinks).
func buildZip(t *testing.T, files []archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range files {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

type archiveEntry struct {
	name     string
	body     string
	linkname string // non-empty → symlink entry
	isDir    bool
}

// TestHTTPFetch_ExtractsTarGz — happy path: a small tar.gz with nested
// content extracts into dest with the right tree layout and bodies.
func TestHTTPFetch_ExtractsTarGz(t *testing.T) {
	body := buildTarGz(t, []archiveEntry{
		{name: "a.txt", body: "alpha"},
		{name: "sub/", isDir: true},
		{name: "sub/b.txt", body: "bravo"},
	})
	fix := newArchiveFixture(t, body, "application/gzip", "/x.tar.gz", `"v1"`)
	dest := filepath.Join(t.TempDir(), "tree")
	recordDestUnder(t, dest)

	src, err := NewHTTP(HTTPConfig{URL: fix.srv.URL + fix.urlPath, Extract: true})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	res, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.Changed || res.FilesTouched < 2 {
		t.Fatalf("Result = %+v; want Changed=true and FilesTouched≥2", res)
	}

	assertFile(t, filepath.Join(dest, "a.txt"), "alpha")
	assertFile(t, filepath.Join(dest, "sub", "b.txt"), "bravo")
}

// TestHTTPFetch_ExtractsZip — same content as a zip.
func TestHTTPFetch_ExtractsZip(t *testing.T) {
	body := buildZip(t, []archiveEntry{
		{name: "a.txt", body: "alpha"},
		{name: "sub/b.txt", body: "bravo"},
	})
	fix := newArchiveFixture(t, body, "application/zip", "/x.zip", `"v1"`)
	dest := filepath.Join(t.TempDir(), "tree")
	recordDestUnder(t, dest)

	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + fix.urlPath, Extract: true})
	if _, err := src.Fetch(context.Background(), dest); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	assertFile(t, filepath.Join(dest, "a.txt"), "alpha")
	assertFile(t, filepath.Join(dest, "sub", "b.txt"), "bravo")
}

// TestHTTPFetch_RefusesTarXz — tar.xz support is intentionally deferred
// to v2 to avoid adding github.com/ulikunitz/xz to sdk/go.mod for v1.
// The refusal must be explicit (ErrInvalidConfig at the URL/Content-Type
// detection step) rather than a confusing "unknown archive type".
func TestHTTPFetch_RefusesTarXz(t *testing.T) {
	body := []byte("xz body — content irrelevant; type detection happens first")
	for _, ct := range []string{"application/x-xz", "application/x-tar+xz"} {
		t.Run("contentType="+ct, func(t *testing.T) {
			fix := newArchiveFixture(t, body, ct, "/x.tar.xz", `"v1"`)
			dest := filepath.Join(t.TempDir(), "tree")
			recordDestUnder(t, dest)
			src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + fix.urlPath, Extract: true})
			_, err := src.Fetch(context.Background(), dest)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Fetch err = %v; want errors.Is(..., ErrInvalidConfig) for tar.xz", err)
			}
		})
	}
}

// TestHTTPFetch_RejectsTraversalEntries — a tar with ../../etc/passwd
// must surface as ErrUnsafeDestination AND leave nothing under dest.
// The "nothing under dest" check guards against partial extracts: even
// if the bad entry came last, no earlier entries should have landed.
func TestHTTPFetch_RejectsTraversalEntries(t *testing.T) {
	body := buildTarGz(t, []archiveEntry{
		{name: "ok.txt", body: "innocuous"},
		{name: "../../etc/passwd", body: "evil"},
	})
	fix := newArchiveFixture(t, body, "application/gzip", "/x.tar.gz", `"v1"`)
	dest := filepath.Join(t.TempDir(), "tree")
	recordDestUnder(t, dest)
	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + fix.urlPath, Extract: true})

	_, err := src.Fetch(context.Background(), dest)
	if !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("Fetch err = %v; want errors.Is(..., ErrUnsafeDestination)", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("dest should not exist after traversal rejection: %v", statErr)
	}
}

// TestHTTPFetch_RejectsAbsoluteEntries — same shape, absolute path.
func TestHTTPFetch_RejectsAbsoluteEntries(t *testing.T) {
	body := buildTarGz(t, []archiveEntry{
		{name: "/etc/passwd", body: "x"},
	})
	fix := newArchiveFixture(t, body, "application/gzip", "/x.tar.gz", `"v1"`)
	dest := filepath.Join(t.TempDir(), "tree")
	recordDestUnder(t, dest)
	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + fix.urlPath, Extract: true})

	_, err := src.Fetch(context.Background(), dest)
	if !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("Fetch err = %v; want errors.Is(..., ErrUnsafeDestination)", err)
	}
}

// TestHTTPFetch_RejectsSymlinksEscapingDest — even a relative-looking
// symlink target that resolves to a path outside dest must be refused.
// The simplest implementation is "reject ALL symlink entries", which is
// what we want for v1 anyway (symlinks rarely matter for content
// distribution).
func TestHTTPFetch_RejectsSymlinkEntries(t *testing.T) {
	body := buildTarGz(t, []archiveEntry{
		{name: "link", linkname: "/tmp"},
	})
	fix := newArchiveFixture(t, body, "application/gzip", "/x.tar.gz", `"v1"`)
	dest := filepath.Join(t.TempDir(), "tree")
	recordDestUnder(t, dest)
	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + fix.urlPath, Extract: true})

	_, err := src.Fetch(context.Background(), dest)
	if !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("Fetch err = %v; want errors.Is(..., ErrUnsafeDestination)", err)
	}
}

// TestHTTPFetch_ArchiveSizeCap — declared cumulative decompressed size
// exceeds MaxBytes → ErrIntegrity. Mirrors the single-file size guard.
func TestHTTPFetch_ArchiveSizeCap(t *testing.T) {
	body := buildTarGz(t, []archiveEntry{
		{name: "big.bin", body: strings.Repeat("x", 4*1024)},
	})
	fix := newArchiveFixture(t, body, "application/gzip", "/x.tar.gz", `"v1"`)
	dest := filepath.Join(t.TempDir(), "tree")
	recordDestUnder(t, dest)
	src, _ := NewHTTP(HTTPConfig{URL: fix.srv.URL + fix.urlPath, Extract: true, MaxBytes: 1024})
	_, err := src.Fetch(context.Background(), dest)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Fetch err = %v; want errors.Is(..., ErrIntegrity)", err)
	}
}

// FuzzHTTPArchive_Tar — random bytes fed as tar.gz input. The fuzz
// target asserts the extractor never panics and never writes outside
// the dest dir, regardless of the input shape.
func FuzzHTTPArchive_Tar(f *testing.F) {
	// Seed with a few representative bytes streams: minimal gzip header,
	// truncated tar, the happy-path archive.
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00})
	f.Add(buildTarGz(&testing.T{}, []archiveEntry{{name: "x", body: "y"}}))

	f.Fuzz(func(t *testing.T, body []byte) {
		// Controlled parent: t.TempDir() gives us a unique dir for this
		// iteration. Using os.TempDir() directly races with the test
		// framework's own scratch files and produces flaky false
		// positives.
		parent := t.TempDir()
		dest := filepath.Join(parent, "dest")
		if err := os.MkdirAll(dest, 0o700); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}

		// Drive the extractor directly via the package-internal entry
		// point — no need to spin up an httptest server per iteration.
		_ = extractTarGzBytes(body, dest, 1<<20)

		// Pass criteria: no panic (Fuzz framework catches it), and the
		// parent directory contains only `dest`. Any other entry means
		// the extractor escaped staging.
		ents := dirEntries(t, parent)
		if len(ents) != 1 || ents[0] != "dest" {
			t.Fatalf("extractor wrote outside dest: parent now contains %v", ents)
		}
	})
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s content = %q; want %q", path, got, want)
	}
}

// extractTarGzBytes is the package-internal entry point the fuzzer
// targets. It must be safe to call with arbitrary bytes — no panics,
// no out-of-dest writes — even on adversarial input.
var _ = io.EOF // anchor for the imports the fuzz target may pull in
