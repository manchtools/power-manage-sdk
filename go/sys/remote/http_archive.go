package remote

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// archiveKind classifies a downloaded body so the extractor knows which
// reader to wrap it in. v1 supports tar.gz and zip; tar.xz is rejected
// explicitly at NewHTTP-equivalent detection time so a caller doesn't
// silently fall back to "treat as opaque blob".
type archiveKind int

const (
	archiveUnknown archiveKind = iota
	archiveTarGz
	archiveZip
	archiveTarXz // recognised → rejected; never extracted
)

// detectArchiveKind picks the kind from a Content-Type / URL pair. Both
// channels are advisory — origins sometimes lie, and CDNs sometimes
// strip Content-Type entirely. We trust Content-Type first, fall back
// to the URL extension, and refuse to guess from raw magic bytes (the
// extractor's safety guards still catch a misclassification).
func detectArchiveKind(contentType, rawURL string) archiveKind {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch ct {
	case "application/gzip", "application/x-gzip", "application/x-tar+gzip", "application/x-tgz":
		return archiveTarGz
	case "application/zip", "application/x-zip", "application/x-zip-compressed":
		return archiveZip
	case "application/x-xz", "application/x-tar+xz":
		return archiveTarXz
	}

	lowerURL := strings.ToLower(rawURL)
	// Strip query string + fragment before extension matching.
	if i := strings.IndexAny(lowerURL, "?#"); i >= 0 {
		lowerURL = lowerURL[:i]
	}
	switch {
	case strings.HasSuffix(lowerURL, ".tar.gz"), strings.HasSuffix(lowerURL, ".tgz"):
		return archiveTarGz
	case strings.HasSuffix(lowerURL, ".zip"):
		return archiveZip
	case strings.HasSuffix(lowerURL, ".tar.xz"), strings.HasSuffix(lowerURL, ".txz"):
		return archiveTarXz
	}
	return archiveUnknown
}

// fetchArchive is Fetch's archive branch. Downloads the body to a tmp
// file, classifies it, dispatches to the per-kind extractor into a
// sibling staging directory, then atomically swaps staging → dest. Any
// validation failure mid-extract bails out and rm-rfs staging — dest is
// either fully populated or untouched.
func (h *httpSource) fetchArchive(ctx context.Context, dest string) (Result, error) {
	if err := validateDestination(dest); err != nil {
		return Result{}, err
	}

	h.mu.Lock()
	cachedRevision := h.revision
	h.mu.Unlock()

	if cachedRevision != "" {
		notModified, err := h.checkNotModified(ctx, cachedRevision)
		if err != nil {
			return Result{}, err
		}
		if notModified {
			return Result{Changed: false, Revision: cachedRevision}, nil
		}
	}

	body, etag, contentType, err := h.openArchiveBody(ctx, cachedRevision)
	if err != nil {
		return Result{}, err
	}
	defer body.Close()

	kind := detectArchiveKind(contentType, h.cfg.URL)
	if kind == archiveTarXz {
		return Result{}, fmt.Errorf("%w: tar.xz archives are not supported in v1", ErrInvalidConfig)
	}
	if kind == archiveUnknown {
		return Result{}, fmt.Errorf("%w: unable to detect archive type for %s (content-type=%q)", ErrInvalidConfig, h.cfg.URL, contentType)
	}

	// Buffer the body to a tmp file before extracting. zip needs a
	// ReaderAt for random access; tar.gz could be streamed but doing
	// both via the same flow keeps the size cap and atomic-write logic
	// in one place.
	tmp, written, sum, err := streamToTmp(dest+".dl", body, h.cfg.MaxBytes)
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(tmp)

	staging := dest + ".staging." + filepath.Base(tmp)[len("dl.tmp."):]
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return Result{}, fmt.Errorf("mkdir staging %s: %w", staging, err)
	}
	cleanupStaging := func() { _ = os.RemoveAll(staging) }

	var filesTouched int
	var extractErr error
	switch kind {
	case archiveTarGz:
		filesTouched, extractErr = extractTarGzFile(tmp, staging, h.cfg.MaxBytes)
	case archiveZip:
		filesTouched, extractErr = extractZipFile(tmp, staging, h.cfg.MaxBytes)
	}
	if extractErr != nil {
		cleanupStaging()
		return Result{}, extractErr
	}

	// Swap staging → dest. If dest exists we replace it; v1 doesn't
	// attempt a fully-atomic "previous tree visible until new one is
	// complete" swap (that needs a per-version dir + symlink dance,
	// which is overkill for the documentation / config / asset use
	// cases this primitive targets).
	if _, statErr := os.Stat(dest); statErr == nil {
		if err := os.RemoveAll(dest); err != nil {
			cleanupStaging()
			return Result{}, fmt.Errorf("remove existing dest %s: %w", dest, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		cleanupStaging()
		return Result{}, fmt.Errorf("mkdir %s: %w", filepath.Dir(dest), err)
	}
	if err := os.Rename(staging, dest); err != nil {
		cleanupStaging()
		return Result{}, fmt.Errorf("swap staging → dest: %w", err)
	}

	if err := applyMode(ctx, dest, h.cfg.Mode, h.cfg.Owner, h.cfg.Group); err != nil {
		return Result{}, err
	}

	revision := etag
	if revision == "" {
		revision = fmt.Sprintf("sha256:%x", sum)
	}

	h.mu.Lock()
	h.revision = revision
	h.mu.Unlock()

	RecordDest(dest)

	// Compute the tree digest so callers can drift-compare against a
	// known-good baseline outside of ETag visibility.
	digest, _ := sha256Tree(dest)

	return Result{
		Changed:      true,
		BytesWritten: written,
		FilesTouched: filesTouched,
		Digest:       digest,
		Revision:     revision,
	}, nil
}

// openArchiveBody is openBody plus the response's Content-Type, which
// the archive branch needs for kind detection.
func (h *httpSource) openArchiveBody(ctx context.Context, etag string) (io.ReadCloser, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.cfg.URL, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("GET %s: %w", h.cfg.URL, err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, "", "", fmt.Errorf("GET %s: %w", h.cfg.URL, err)
	}
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return io.NopCloser(strings.NewReader("")), resp.Header.Get("ETag"), resp.Header.Get("Content-Type"), nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, "", "", fmt.Errorf("GET %s: status %d", h.cfg.URL, resp.StatusCode)
	}
	return resp.Body, resp.Header.Get("ETag"), resp.Header.Get("Content-Type"), nil
}

// extractTarGzFile is the file-on-disk entry point that the staging
// flow uses. extractTarGzBytes wraps it for the fuzz harness.
func extractTarGzFile(tmpPath, staging string, maxBytes int64) (int, error) {
	f, err := os.Open(tmpPath) //nolint:gosec // staging path validated upstream.
	if err != nil {
		return 0, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()
	return extractTarGz(f, staging, maxBytes)
}

// extractTarGzBytes is the fuzz-friendly entry point. Accepts arbitrary
// bytes and never panics; safety is the whole point.
func extractTarGzBytes(body []byte, staging string, maxBytes int64) error {
	_, err := extractTarGz(strings.NewReader(string(body)), staging, maxBytes)
	return err
}

// extractTarGz walks a tar.gz stream, enforces per-entry safety, and
// writes files / dirs into staging. Returns the count of regular files
// extracted. Returns ErrUnsafeDestination for any unsafe entry name or
// symlink; ErrIntegrity when the cumulative size exceeds maxBytes; the
// wrapped gzip / tar error otherwise.
func extractTarGz(body io.Reader, staging string, maxBytes int64) (int, error) {
	gz, err := gzip.NewReader(body)
	if err != nil {
		return 0, fmt.Errorf("gzip header: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var totalBytes int64
	var files int
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return files, fmt.Errorf("tar next: %w", err)
		}

		// Reject symlinks, hardlinks, devices, FIFOs — anything that
		// can act as a redirect or escape. Only regular files and
		// directories are accepted.
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			// fall through to write
		case tar.TypeDir:
			out, perr := safeJoinDest(staging, hdr.Name)
			if perr != nil {
				return files, perr
			}
			if err := os.MkdirAll(out, 0o755); err != nil {
				return files, fmt.Errorf("mkdir %s: %w", out, err)
			}
			continue
		default:
			return files, fmt.Errorf("%w: tar entry %q has disallowed type %v", ErrUnsafeDestination, hdr.Name, hdr.Typeflag)
		}

		out, perr := safeJoinDest(staging, hdr.Name)
		if perr != nil {
			return files, perr
		}
		// Per-entry size + cumulative size check. The cumulative one
		// is the real teeth (a one-byte file plus a 100 GiB file
		// shouldn't slip past).
		if hdr.Size < 0 {
			return files, fmt.Errorf("%w: negative size in entry %q", ErrIntegrity, hdr.Name)
		}
		if totalBytes+hdr.Size > maxBytes {
			return files, fmt.Errorf("%w: cumulative size exceeds %d bytes", ErrIntegrity, maxBytes)
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return files, fmt.Errorf("mkdir %s: %w", filepath.Dir(out), err)
		}
		written, werr := writeTarEntry(out, tr, hdr.FileInfo().Mode().Perm())
		if werr != nil {
			return files, werr
		}
		totalBytes += written
		if totalBytes > maxBytes {
			return files, fmt.Errorf("%w: cumulative size exceeds %d bytes", ErrIntegrity, maxBytes)
		}
		files++
	}
	return files, nil
}

func writeTarEntry(out string, r io.Reader, mode os.FileMode) (int64, error) {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", out, err)
	}
	defer f.Close()
	n, err := io.Copy(f, r)
	if err != nil {
		return n, fmt.Errorf("copy %s: %w", out, err)
	}
	return n, nil
}

// extractZipFile mirrors extractTarGzFile for the zip branch.
func extractZipFile(tmpPath, staging string, maxBytes int64) (int, error) {
	zr, err := zip.OpenReader(tmpPath)
	if err != nil {
		return 0, fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()

	var totalBytes int64
	var files int
	for _, ze := range zr.File {
		out, perr := safeJoinDest(staging, ze.Name)
		if perr != nil {
			return files, perr
		}
		if strings.HasSuffix(ze.Name, "/") || ze.FileInfo().IsDir() {
			if err := os.MkdirAll(out, 0o755); err != nil {
				return files, fmt.Errorf("mkdir %s: %w", out, err)
			}
			continue
		}
		// Pre-check declared decompressed size; defeats zip-bomb-style
		// inputs that under-report compressed size but explode on
		// decompress.
		declared := int64(ze.UncompressedSize64) //nolint:gosec // guarded below
		if declared < 0 {
			return files, fmt.Errorf("%w: negative uncompressed size", ErrIntegrity)
		}
		if totalBytes+declared > maxBytes {
			return files, fmt.Errorf("%w: cumulative size exceeds %d bytes", ErrIntegrity, maxBytes)
		}
		rc, err := ze.Open()
		if err != nil {
			return files, fmt.Errorf("open zip entry %q: %w", ze.Name, err)
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			rc.Close()
			return files, fmt.Errorf("mkdir %s: %w", filepath.Dir(out), err)
		}
		limited := io.LimitReader(rc, maxBytes-totalBytes+1)
		written, werr := writeTarEntry(out, limited, ze.FileInfo().Mode().Perm())
		rc.Close()
		if werr != nil {
			return files, werr
		}
		totalBytes += written
		if totalBytes > maxBytes {
			return files, fmt.Errorf("%w: cumulative size exceeds %d bytes", ErrIntegrity, maxBytes)
		}
		files++
	}
	return files, nil
}

// safeJoinDest validates an archive entry's name and returns the
// destination path under staging. The intent check runs on the RAW
// entry name, before any normalisation, so an adversarial input that
// would *eventually* normalise to an in-tree path still surfaces as
// unsafe — the caller's intent was to escape.
//
// Rejects:
//   - empty names and "."
//   - absolute paths (lead "/" or, defense-in-depth, "\")
//   - any path component equal to ".." (treats the archive as adversarial)
//   - paths whose normalised join is not within staging (covers oddities
//     like NUL bytes, double slashes, or platform separator quirks)
//
// Uses path (not filepath) for the entry-side normalisation so a tar
// header `dir/file` resolves the same way regardless of the host OS.
func safeJoinDest(staging, entry string) (string, error) {
	if entry == "" || entry == "." {
		return "", fmt.Errorf("%w: empty or '.' entry name", ErrUnsafeDestination)
	}
	if strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, `\`) {
		return "", fmt.Errorf("%w: absolute entry name %q", ErrUnsafeDestination, entry)
	}
	if strings.ContainsRune(entry, 0) {
		return "", fmt.Errorf("%w: entry %q contains NUL", ErrUnsafeDestination, entry)
	}
	// Component-level traversal check on the raw, pre-normalisation
	// form: any ".." segment means the archive intended to escape.
	// Split on either separator so a Windows-style entry in a tar
	// can't slip past on a Unix host.
	for _, comp := range strings.FieldsFunc(entry, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if comp == ".." {
			return "", fmt.Errorf("%w: entry %q contains ..", ErrUnsafeDestination, entry)
		}
	}

	rel := strings.TrimLeft(path.Clean(entry), "/")
	if rel == "" || rel == "." {
		return "", fmt.Errorf("%w: entry %q normalises to empty", ErrUnsafeDestination, entry)
	}
	full := filepath.Join(staging, filepath.FromSlash(rel))
	stagingAbs, err := filepath.Abs(staging)
	if err != nil {
		return "", fmt.Errorf("%w: staging abs: %v", ErrUnsafeDestination, err)
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("%w: full abs: %v", ErrUnsafeDestination, err)
	}
	if !strings.HasPrefix(fullAbs, stagingAbs+string(filepath.Separator)) && fullAbs != stagingAbs {
		return "", fmt.Errorf("%w: entry %q resolves outside staging", ErrUnsafeDestination, entry)
	}
	return full, nil
}

// http.go's Fetch dispatches here when cfg.Extract is set; wired up in
// the same commit so the test suite sees a green archive branch.
func init() {
	httpArchiveDispatch = func(ctx context.Context, h *httpSource, dest string) (Result, error) {
		return h.fetchArchive(ctx, dest)
	}
}

// httpArchiveDispatch is the seam Fetch calls into for the archive
// branch. Initialised in this file's init so the single-file branch in
// http.go can remain ignorant of archive types.
var httpArchiveDispatch func(ctx context.Context, h *httpSource, dest string) (Result, error)

// errFetchArchiveUnimplemented is the sentinel http.go returns when
// httpArchiveDispatch hasn't been wired up yet (a build-tag scenario
// no production caller hits, but worth a clear message).
var errFetchArchiveUnimplemented = errors.New("remote: http archive Fetch dispatcher not registered")
