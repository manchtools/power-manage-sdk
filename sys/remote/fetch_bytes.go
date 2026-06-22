package remote

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

// defaultBytesMaxBytes bounds an in-memory FetchBytes when the caller leaves
// MaxBytes unset. It is far smaller than the file-fetch default
// (defaultHTTPMaxBytes, 2 GiB) because the whole body is buffered in RAM: 64 MiB
// comfortably covers a GPG key or a SHA256SUMS manifest while refusing a
// memory-exhaustion stream from a compromised origin.
const defaultBytesMaxBytes int64 = 64 * 1024 * 1024

// FetchBytes downloads the configured HTTP payload entirely into memory,
// applying the SAME guards as Fetch — URL/scheme validation, the MaxBytes cap,
// the optional sha256 pin, and the default-or-injected client — but bounded for
// RAM. It is for SMALL payloads (a GPG key, a SHA256SUMS manifest), NOT large
// artifacts: use Fetch (streamed, atomic, to a file) for those.
//
// When cfg.MaxBytes is unset it defaults to defaultBytesMaxBytes (64 MiB), NOT
// the 2 GiB file default, so a runaway or compromised origin cannot exhaust
// memory. A body exceeding the cap fails closed with ErrIntegrity and returns no
// data, and a set ChecksumSHA256 is verified before the bytes are returned.
// Extract/Prune are archive-to-directory concepts and are rejected here.
func FetchBytes(ctx context.Context, cfg HTTPConfig) ([]byte, error) {
	if cfg.Extract || cfg.Prune {
		return nil, fmt.Errorf("%w: extract/prune are not valid for FetchBytes (single in-memory payload)", ErrInvalidConfig)
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultBytesMaxBytes
	}

	h, err := newHTTPSource(cfg)
	if err != nil {
		return nil, err
	}

	body, _, err := h.openBody(ctx, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()

	// LimitReader caps at MaxBytes+1 so a one-byte over-read tells us the origin
	// tried to deliver more than we allow — surfaced as ErrIntegrity, same bucket
	// as a size-cap breach in the file path.
	data, err := io.ReadAll(io.LimitReader(body, h.cfg.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", h.cfg.URL, err)
	}
	if int64(len(data)) > h.cfg.MaxBytes {
		return nil, fmt.Errorf("%w: payload exceeds %d bytes", ErrIntegrity, h.cfg.MaxBytes)
	}

	if h.checksum != nil {
		sum := sha256.Sum256(data)
		if subtle.ConstantTimeCompare(sum[:], h.checksum) != 1 {
			return nil, fmt.Errorf("%w: sha256 mismatch for %s", ErrIntegrity, h.cfg.URL)
		}
	}

	return data, nil
}
