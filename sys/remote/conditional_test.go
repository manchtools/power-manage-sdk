package remote

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// condServer serves body with an ETag and honours If-None-Match with a 304 —
// the conditional-request path the per-test fixtures don't model.
func condServer(t *testing.T, body []byte, etag, contentType string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestArchive_NotModifiedNoOp — a second archive Fetch into the same dest sends
// the stored ETag and gets a 304, so it is a no-op (openArchiveBody's 304 branch
// + fetchArchive's not-modified short-circuit).
func TestArchive_NotModifiedNoOp(t *testing.T) {
	body := buildTarGz(t, []archiveEntry{{name: "f", body: "x"}})
	srv := condServer(t, body, "arch-etag", "application/gzip")
	src, err := NewHTTP(HTTPConfig{URL: srv.URL + "/a.tar.gz", Extract: true})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	res1, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("Fetch #1: %v", err)
	}
	if !res1.Changed {
		t.Fatal("first archive Fetch: Changed=false")
	}
	res2, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("Fetch #2: %v", err)
	}
	if res2.Changed {
		t.Error("second archive Fetch with an unchanged ETag: Changed=true (304 not honoured)")
	}
}

// TestS3_HeadNotModifiedNoOp — a second single-key S3 Fetch HEADs with the stored
// ETag, gets 304, and skips the GET (headNotModified's 304 branch).
func TestS3_HeadNotModifiedNoOp(t *testing.T) {
	srv := condServer(t, []byte("payload"), "s3-etag", "")
	src, err := NewS3(S3Config{Endpoint: srv.URL, Bucket: "b", Key: "k"})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if _, err := src.Fetch(context.Background(), dest); err != nil {
		t.Fatalf("Fetch #1: %v", err)
	}
	res2, err := src.Fetch(context.Background(), dest)
	if err != nil {
		t.Fatalf("Fetch #2: %v", err)
	}
	if res2.Changed {
		t.Error("second S3 Fetch with an unchanged ETag: Changed=true (304 not honoured)")
	}
}
