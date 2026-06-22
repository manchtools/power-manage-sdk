package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// TestRemote_NormalizesPaddedURL (Gap 14): a whitespace-padded but otherwise
// valid URL — which sdk.ValidateHTTPSURL accepts, since it trims before parsing
// — must be accepted by NewHTTP/Fetch and FetchBytes too. Otherwise "validation
// passed" does not imply "the fetch accepts it", and a caller that validated up
// front fails mysteriously at fetch time.
func TestRemote_NormalizesPaddedURL(t *testing.T) {
	fix := newHTTPFixture(t, []byte("ok"), `"v1"`)
	padded := "  " + fix.srv.URL + "/x\n"

	data, err := FetchBytes(context.Background(), HTTPConfig{URL: padded})
	if err != nil {
		t.Fatalf("FetchBytes rejected a padded URL the validator accepts: %v", err)
	}
	if string(data) != "ok" {
		t.Errorf("data = %q, want ok", data)
	}

	dest := filepath.Join(t.TempDir(), "f")
	recordDestUnder(t, dest)
	src, err := NewHTTP(HTTPConfig{URL: padded})
	if err != nil {
		t.Fatalf("NewHTTP rejected a padded URL: %v", err)
	}
	if _, err := src.Fetch(context.Background(), dest); err != nil {
		t.Fatalf("Fetch with padded URL: %v", err)
	}
}

// TestFetchBytes_ReturnsBody — the value case: a small payload (a GPG key, a
// checksum manifest) is returned in memory.
func TestFetchBytes_ReturnsBody(t *testing.T) {
	payload := []byte("gpg-key-or-sha256sums-manifest")
	fix := newHTTPFixture(t, payload, `"v1"`)
	data, err := FetchBytes(context.Background(), HTTPConfig{URL: fix.srv.URL + "/x"})
	if err != nil {
		t.Fatalf("FetchBytes: %v", err)
	}
	if string(data) != string(payload) {
		t.Errorf("data = %q, want %q", data, payload)
	}
}

// TestFetchBytes_EnforcesMaxBytes is the security test (Gap 12): a body that
// exceeds the cap must fail closed with ErrIntegrity and return no data — this
// is the bound the agent's uncapped bufio.Scanner manifest read lacked.
func TestFetchBytes_EnforcesMaxBytes(t *testing.T) {
	fix := newHTTPFixture(t, nil, `"v1"`)
	fix.getDelay = func(w io.Writer) {
		buf := make([]byte, 1024)
		for i := 0; i < 10; i++ { // stream 10 KiB while the cap is 1 KiB
			_, _ = w.Write(buf)
		}
	}
	data, err := FetchBytes(context.Background(), HTTPConfig{URL: fix.srv.URL + "/x", MaxBytes: 1024})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v, want ErrIntegrity for an over-cap body", err)
	}
	if data != nil {
		t.Errorf("an over-cap fetch must return nil data, got %d bytes", len(data))
	}
}

// TestFetchBytes_InMemoryDefaultIsSmall guards the OOM property: when MaxBytes is
// unset, FetchBytes must default to a SMALL in-memory cap, never the 2 GiB
// file-fetch default (buffering 2 GiB in RAM is the DoS this primitive closes).
func TestFetchBytes_InMemoryDefaultIsSmall(t *testing.T) {
	if defaultBytesMaxBytes >= defaultHTTPMaxBytes {
		t.Fatalf("in-memory default cap %d must be far below the file default %d", defaultBytesMaxBytes, defaultHTTPMaxBytes)
	}
}

func TestFetchBytes_ChecksumMatchAndMismatch(t *testing.T) {
	payload := []byte("manifest-body")
	sum := sha256.Sum256(payload)
	fix := newHTTPFixture(t, payload, `"v1"`)

	data, err := FetchBytes(context.Background(), HTTPConfig{URL: fix.srv.URL + "/x", ChecksumSHA256: hex.EncodeToString(sum[:])})
	if err != nil || string(data) != string(payload) {
		t.Fatalf("matching checksum: data=%q err=%v", data, err)
	}

	if _, err := FetchBytes(context.Background(), HTTPConfig{URL: fix.srv.URL + "/x", ChecksumSHA256: strings.Repeat("0", 64)}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("mismatched checksum err = %v, want ErrIntegrity", err)
	}
}

func TestFetchBytes_RejectsExtractAndBadScheme(t *testing.T) {
	if _, err := FetchBytes(context.Background(), HTTPConfig{URL: "https://example.com/y", Extract: true}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("Extract must be rejected for a memory fetch: %v", err)
	}
	if _, err := FetchBytes(context.Background(), HTTPConfig{URL: "file:///etc/passwd"}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("a non-http(s) scheme must be rejected: %v", err)
	}
}

// TestFetchBytes_InjectedTLSClient: the same E1 transport seam works for the
// in-memory path, so a consumer can test against an httptest TLS server.
func TestFetchBytes_InjectedTLSClient(t *testing.T) {
	payload := []byte("delivered-over-tls")
	srv := newTLSFixture(t, payload)
	data, err := FetchBytes(context.Background(), HTTPConfig{URL: srv.URL + "/x", Client: srv.Client()})
	if err != nil {
		t.Fatalf("FetchBytes over injected TLS client: %v", err)
	}
	if string(data) != string(payload) {
		t.Errorf("data = %q, want %q", data, payload)
	}
}
