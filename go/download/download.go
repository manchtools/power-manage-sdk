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
	defer f.Close()

	checksum, err := Download(ctx, client, url, f, maxSize)
	if err != nil {
		os.Remove(dest)
		return err
	}

	if !strings.EqualFold(checksum, expectedSHA256) {
		os.Remove(dest)
		return fmt.Errorf("checksum mismatch: got %s, want %s", checksum, expectedSHA256)
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
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first whitespace sequence.
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		hash := parts[0]
		name := parts[1]

		// Strip common prefixes.
		name = strings.TrimPrefix(name, "./")
		name = strings.TrimPrefix(name, "*")

		if name == filename {
			return hash, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read checksums: %w", err)
	}

	return "", fmt.Errorf("checksum not found for %q", filename)
}
