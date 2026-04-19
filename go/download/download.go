// Package download provides utilities for downloading files over HTTP
// with size limits and SHA256 checksum verification.
package download

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// DefaultMaxSize is the default maximum download size (2 GiB).
const DefaultMaxSize int64 = 2 << 30

// Download downloads a URL to dst file, returns SHA256 hex checksum.
// The caller is responsible for creating and closing dst.
// If maxSize is <= 0, DefaultMaxSize is used.
func Download(ctx context.Context, client *http.Client, url string, dst *os.File, maxSize int64) (checksum string, err error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %s", resp.Status)
	}

	// Reject early if Content-Length exceeds limit.
	if resp.ContentLength > maxSize {
		return "", fmt.Errorf("content length %d exceeds max size %d", resp.ContentLength, maxSize)
	}

	hasher := sha256.New()
	limited := io.LimitReader(resp.Body, maxSize+1)
	writer := io.MultiWriter(dst, hasher)

	n, err := io.Copy(writer, limited)
	if err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}

	if n > maxSize {
		return "", fmt.Errorf("download size %d exceeds max size %d", n, maxSize)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// DownloadAndVerify downloads a URL to dest path, verifies SHA256 matches expected.
// If maxSize is <= 0, DefaultMaxSize is used.
func DownloadAndVerify(ctx context.Context, client *http.Client, url, dest, expectedSHA256 string, maxSize int64) error {
	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	cleanup := func() {
		f.Close()
		os.Remove(dest)
	}

	checksum, err := Download(ctx, client, url, f, maxSize)
	if err != nil {
		cleanup()
		return err
	}

	if !strings.EqualFold(checksum, expectedSHA256) {
		cleanup()
		return fmt.Errorf("checksum mismatch: got %s, want %s", checksum, expectedSHA256)
	}

	if err := f.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync file: %w", err)
	}

	if err := f.Close(); err != nil {
		// Sync already flushed, so the data is on disk — but a Close
		// error can surface a stacked write error the OS only
		// reported at close time. Remove the file so the next run
		// re-downloads rather than treating a possibly-corrupt file
		// as good.
		os.Remove(dest)
		return fmt.Errorf("close file: %w", err)
	}
	return nil
}

// ExtractChecksum parses a SHA256SUMS-style file from reader and returns
// the checksum for the given filename.
//
// Supported formats:
//
//	<hash>  <filename>       (double-space, GNU coreutils default)
//	<hash> <filename>        (single-space)
//	<hash>  ./<filename>     (./ prefix)
//	<hash>  *<filename>      (* prefix for binary mode)
func ExtractChecksum(reader io.Reader, filename string) (string, error) {
	// Normalize the input filename the same way we normalize parsed names.
	filename = strings.TrimPrefix(filename, "./")
	filename = strings.TrimPrefix(filename, "*")

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split hash from filename on first whitespace.
		// SHA256SUMS uses "hash  filename" (two spaces) or "hash *filename".
		idx := strings.IndexAny(line, " \t")
		if idx < 0 {
			continue
		}
		hash := strings.ToLower(line[:idx])
		name := strings.TrimLeft(line[idx:], " \t")

		// Strip common prefixes.
		name = strings.TrimPrefix(name, "./")
		name = strings.TrimPrefix(name, "*")

		if name == filename {
			// Validate that the hash looks like a valid SHA256 hex string.
			if len(hash) != 64 {
				return "", fmt.Errorf("invalid checksum length %d for %q (expected 64 hex chars)", len(hash), filename)
			}
			for _, c := range hash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					return "", fmt.Errorf("invalid hex character %q in checksum for %q", string(c), filename)
				}
			}
			return hash, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read checksums: %w", err)
	}

	return "", fmt.Errorf("checksum not found for %q", filename)
}
