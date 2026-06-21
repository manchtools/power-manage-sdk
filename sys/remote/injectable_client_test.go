package remote

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTLSFixture serves payload over TLS with a self-signed httptest cert. The
// default HTTP client rejects that cert, so a Fetch can only succeed if the
// caller injects srv.Client() via HTTPConfig.Client — exactly the seam under
// test.
func newTLSFixture(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestHTTPFetch_InjectedClient_ReachesTLSServer is the value case: with a
// caller-supplied client that trusts the test server's cert, Fetch downloads
// and atomically writes the payload. Without the injectable client this is
// impossible (the default client won't trust a self-signed httptest cert) —
// which is why a consumer could not delegate its own download to remote.Fetch.
func TestHTTPFetch_InjectedClient_ReachesTLSServer(t *testing.T) {
	payload := []byte("delivered over TLS")
	srv := newTLSFixture(t, payload)
	dest := filepath.Join(t.TempDir(), "file")
	recordDestUnder(t, dest)

	src, err := NewHTTP(HTTPConfig{URL: srv.URL + "/file", Client: srv.Client()})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	res, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("Fetch over injected TLS client: %v", err)
	}
	if !res.Changed || res.BytesWritten != int64(len(payload)) {
		t.Fatalf("Result = %+v; want Changed with %d bytes", res, len(payload))
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("dest = %q; want %q", got, payload)
	}
}

// TestHTTPFetch_InjectedClient_StillEnforcesChecksum proves the seam is a
// TRANSPORT override only: injecting a client does not bypass the integrity
// pin. A wrong checksum over the injected TLS client still fails closed
// (ErrIntegrity, dest absent).
func TestHTTPFetch_InjectedClient_StillEnforcesChecksum(t *testing.T) {
	srv := newTLSFixture(t, []byte("real body"))
	dest := filepath.Join(t.TempDir(), "file")
	recordDestUnder(t, dest)

	src, err := NewHTTP(HTTPConfig{
		URL:            srv.URL + "/file",
		ChecksumSHA256: strings.Repeat("0", 64),
		Client:         srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if _, err := src.Fetch(context.Background(), dest); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Fetch err = %v; want ErrIntegrity even with an injected client", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("dest must not exist after checksum failure; stat err = %v", err)
	}
}

// TestNewHTTP_NilClientUsesDefault pins the contract that omitting Client keeps
// the hardened default (non-nil) — so existing callers are unchanged.
func TestNewHTTP_NilClientUsesDefault(t *testing.T) {
	src, err := NewHTTP(HTTPConfig{URL: "https://example.com/x"})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if src.(*httpSource).client == nil {
		t.Fatal("nil Client must fall back to the default client, got nil")
	}
}
