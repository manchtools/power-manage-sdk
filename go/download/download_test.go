package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func TestDownload(t *testing.T) {
	content := "hello world\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	f, err := os.CreateTemp(t.TempDir(), "dl-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	checksum, err := Download(context.Background(), srv.Client(), srv.URL, f, DefaultMaxSize)
	if err != nil {
		t.Fatalf("Download error: %v", err)
	}

	want := sha256Hex(content)
	if checksum != want {
		t.Errorf("checksum = %s, want %s", checksum, want)
	}

	// Verify file contents.
	f.Seek(0, 0)
	buf := make([]byte, len(content))
	n, _ := f.Read(buf)
	if string(buf[:n]) != content {
		t.Errorf("file content = %q, want %q", string(buf[:n]), content)
	}
}

func TestDownload_ContentLengthExceedsMax(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "99999")
		w.Write([]byte("small"))
	}))
	defer srv.Close()

	f, err := os.CreateTemp(t.TempDir(), "dl-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	_, err = Download(context.Background(), srv.Client(), srv.URL, f, 512)
	if err == nil {
		t.Fatal("expected error for Content-Length exceeding max size")
	}
	if !strings.Contains(err.Error(), "content length") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDownload_SizeLimitExceeded(t *testing.T) {
	content := strings.Repeat("x", 1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	f, err := os.CreateTemp(t.TempDir(), "dl-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	_, err = Download(context.Background(), srv.Client(), srv.URL, f, 512)
	if err == nil {
		t.Fatal("expected error for size limit exceeded")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDownload_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f, err := os.CreateTemp(t.TempDir(), "dl-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	_, err = Download(context.Background(), srv.Client(), srv.URL, f, DefaultMaxSize)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDownloadAndVerify_Match(t *testing.T) {
	content := "verified content\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	dest := t.TempDir() + "/verified.bin"
	expected := sha256Hex(content)

	err := DownloadAndVerify(context.Background(), srv.Client(), srv.URL, dest, expected, DefaultMaxSize)
	if err != nil {
		t.Fatalf("DownloadAndVerify error: %v", err)
	}

	// Verify file exists and has correct content.
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Errorf("file content = %q, want %q", string(data), content)
	}
}

func TestDownloadAndVerify_Mismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("actual content"))
	}))
	defer srv.Close()

	dest := t.TempDir() + "/bad.bin"
	err := DownloadAndVerify(context.Background(), srv.Client(), srv.URL, dest, "0000000000000000000000000000000000000000000000000000000000000000", DefaultMaxSize)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("unexpected error: %v", err)
	}

	// File should be cleaned up.
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("file should have been removed after checksum mismatch")
	}
}

func TestExtractChecksum(t *testing.T) {
	hash1 := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	hash2 := "1111111111111111111111111111111111111111111111111111111111111111"
	hash3 := "2222222222222222222222222222222222222222222222222222222222222222"
	hash4 := "3333333333333333333333333333333333333333333333333333333333333333"

	tests := []struct {
		name     string
		input    string
		filename string
		want     string
		wantErr  bool
	}{
		{
			name:     "double space format",
			input:    hash1 + "  myfile.tar.gz\n" + hash2 + "  other.tar.gz\n",
			filename: "myfile.tar.gz",
			want:     hash1,
		},
		{
			name:     "single space format",
			input:    hash1 + " myfile.tar.gz\n",
			filename: "myfile.tar.gz",
			want:     hash1,
		},
		{
			name:     "dot-slash prefix",
			input:    hash1 + "  ./myfile.tar.gz\n",
			filename: "myfile.tar.gz",
			want:     hash1,
		},
		{
			name:     "star prefix (binary mode)",
			input:    hash1 + "  *myfile.tar.gz\n",
			filename: "myfile.tar.gz",
			want:     hash1,
		},
		{
			name:     "file not found",
			input:    hash1 + "  other.tar.gz\n",
			filename: "myfile.tar.gz",
			wantErr:  true,
		},
		{
			name:     "empty input",
			input:    "",
			filename: "myfile.tar.gz",
			wantErr:  true,
		},
		{
			name:     "comments and blank lines",
			input:    "# comment\n\n" + hash1 + "  myfile.tar.gz\n",
			filename: "myfile.tar.gz",
			want:     hash1,
		},
		{
			name:     "multiple files pick correct one",
			input:    hash2 + "  file1.bin\n" + hash3 + "  file2.bin\n" + hash4 + "  file3.bin\n",
			filename: "file2.bin",
			want:     hash3,
		},
		{
			name:     "uppercase hex is lowercased",
			input:    "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2  myfile.tar.gz\n",
			filename: "myfile.tar.gz",
			want:     hash1,
		},
		{
			name:     "invalid hex length",
			input:    "abc123  myfile.tar.gz\n",
			filename: "myfile.tar.gz",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractChecksum(strings.NewReader(tt.input), tt.filename)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
