package remote

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SHA-256 helpers. Used by HTTP single-file integrity checks
// (sha256File) and by the tree-digest drift token returned from
// Fetch when the source is an extracted archive, a Git checkout, or
// an S3 prefix (sha256Tree).
//
// The verify package in this SDK exposes signature helpers but no
// file-level sha256 wrapper, so the file-hash + tree-walk live here.
// Both helpers stream in fixed-size chunks; no path's content is ever
// loaded entirely into memory.

// digestBufSize is the per-file read chunk. 64 KiB matches the common
// io.Copy default and keeps memory pressure bounded regardless of input
// size.
const digestBufSize = 64 * 1024

// sha256File returns the hex-encoded sha256 of the file at path. Streams
// the file in fixed-size chunks; never reads the whole body into memory.
func sha256File(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // caller has already validated the path.
	if err != nil {
		return "", fmt.Errorf("sha256File %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	buf := make([]byte, digestBufSize)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", fmt.Errorf("sha256File %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sha256Tree returns the hex-encoded sha256 of the canonicalised tree
// rooted at root. The output depends on:
//
//   - the set of regular file paths under root (relative, slash-separated,
//     lexically sorted),
//   - each file's mode bits (so an executable bit flip changes the digest),
//   - each file's body.
//
// Directories, symlinks, devices, and other non-regular entries are
// skipped (they aren't drift-relevant for the kinds of payloads this
// primitive places: archive extracts, Git checkouts, S3 mirrors).
//
// The canonical form is:
//
//	for each file (in sorted relative-path order):
//	  uint32 path-length || path-bytes
//	  uint32 mode-bits
//	  uint64 file-size
//	  raw file body
//
// Length prefixes prevent a path-rename + body-shift collision (where
// concatenating two unrelated files would otherwise collide with one
// long file).
func sha256Tree(root string) (string, error) {
	rootClean := filepath.Clean(root)

	type entry struct {
		rel  string
		full string
		mode os.FileMode
		size int64
	}
	var files []entry

	walkErr := filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(rootClean, path)
		if rerr != nil {
			return fmt.Errorf("rel %s: %w", path, rerr)
		}
		// Canonicalise on slashes so two hosts (or two OSes) hash the
		// same logical tree to the same digest.
		rel = filepath.ToSlash(rel)
		info, ierr := d.Info()
		if ierr != nil {
			return fmt.Errorf("stat %s: %w", path, ierr)
		}
		files = append(files, entry{rel: rel, full: path, mode: info.Mode().Perm(), size: info.Size()})
		return nil
	})
	if walkErr != nil {
		return "", walkErr
	}

	// Deterministic order across hosts. WalkDir already emits lexical
	// order on most filesystems, but the spec doesn't guarantee it.
	sort.Slice(files, func(i, j int) bool { return strings.Compare(files[i].rel, files[j].rel) < 0 })

	h := sha256.New()
	hdr := make([]byte, 0, 16)
	buf := make([]byte, digestBufSize)
	for _, e := range files {
		// path-length || path
		hdr = hdr[:0]
		hdr = binary.BigEndian.AppendUint32(hdr, uint32(len(e.rel)))
		h.Write(hdr)
		h.Write([]byte(e.rel))
		// mode || size
		hdr = hdr[:0]
		hdr = binary.BigEndian.AppendUint32(hdr, uint32(e.mode))
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(e.size))
		h.Write(hdr)
		// body
		if e.size > 0 {
			f, oerr := os.Open(e.full) //nolint:gosec // tree-walk produced it.
			if oerr != nil {
				return "", fmt.Errorf("open %s: %w", e.full, oerr)
			}
			if _, cerr := io.CopyBuffer(h, f, buf); cerr != nil {
				_ = f.Close()
				return "", fmt.Errorf("read %s: %w", e.full, cerr)
			}
			_ = f.Close()
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
