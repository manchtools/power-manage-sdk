package remote

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// TestArchive_UndetectableType — Extract is requested but neither the
// content-type nor the URL extension identifies an archive kind, so fetchArchive
// must refuse with ErrInvalidConfig rather than guess.
func TestArchive_UndetectableType(t *testing.T) {
	fix := newArchiveFixture(t, []byte("opaque bytes"), "application/octet-stream", "/payload.bin", "")
	src, err := NewHTTP(HTTPConfig{URL: fix.srv.URL + fix.urlPath, Extract: true})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	_, ferr := src.Fetch(context.Background(), filepath.Join(t.TempDir(), "out"))
	if !errors.Is(ferr, ErrInvalidConfig) {
		t.Errorf("Fetch of an undetectable archive = %v; want ErrInvalidConfig", ferr)
	}
}

// TestS3Prefix_PerObjectGetError — during a prefix sync, an object GET that
// fails (500) must surface an error, exercising openSingleObject /
// streamObjectToFile's error path.
func TestS3Prefix_PerObjectGetError(t *testing.T) {
	objs := []s3TestObject{{key: "p/a", body: []byte("x"), etag: "e1"}}
	fix := newS3PrefixFixture(t, "b", "p/", objs)
	fix.getErr = 500
	src, err := NewS3(S3Config{Endpoint: fix.srv.URL, Bucket: "b", Key: "p/"})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	if _, ferr := src.Fetch(context.Background(), t.TempDir()); ferr == nil {
		t.Error("prefix sync with a 500 on an object GET returned nil error")
	}
}
