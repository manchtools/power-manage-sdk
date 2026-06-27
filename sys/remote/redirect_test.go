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

// mkReq builds a bare GET for rawurl — used to drive redirectPolicy directly,
// the way http.Client would call CheckRedirect.
func mkReq(t *testing.T, rawurl string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, rawurl, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q): %v", rawurl, err)
	}
	return r
}

// chain turns a list of URLs into the `via` slice CheckRedirect receives (the
// requests already made, oldest first).
func chain(t *testing.T, urls ...string) []*http.Request {
	t.Helper()
	via := make([]*http.Request, len(urls))
	for i, u := range urls {
		via[i] = mkReq(t, u)
	}
	return via
}

// TestRedirectPolicy covers the pure decision function for every level. It
// includes the https->http downgrade case, which the httptest integration test
// can't reach (the default client rejects a self-signed TLS server before any
// redirect fires), so this is the authoritative branch coverage.
func TestRedirectPolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  RedirectPolicy
		to      string   // the redirect target (req.URL)
		via     []string // prior hops, oldest first
		wantErr bool
	}{
		// RedirectNone refuses everything, even a same-origin path bounce.
		{"none refuses same-origin", RedirectNone, "https://h/b", []string{"https://h/a"}, true},
		{"none refuses cross-host", RedirectNone, "https://h2/b", []string{"https://h/a"}, true},

		// RedirectSameOrigin: path bounce ok, host/scheme change refused.
		{"same-origin allows path bounce", RedirectSameOrigin, "https://h/b", []string{"https://h/a"}, false},
		{"same-origin refuses cross-host", RedirectSameOrigin, "https://h2/b", []string{"https://h/a"}, true},
		{"same-origin refuses port change", RedirectSameOrigin, "https://h:8443/b", []string{"https://h/a"}, true},
		{"same-origin refuses upgrade", RedirectSameOrigin, "https://h/b", []string{"http://h/a"}, true},

		// RedirectCrossOrigin: host change + http->https upgrade ok; downgrade refused.
		{"cross-origin allows cross-host https", RedirectCrossOrigin, "https://h2/b", []string{"https://h/a"}, false},
		{"cross-origin allows http->https upgrade", RedirectCrossOrigin, "https://h2/b", []string{"http://h/a"}, false},
		{"cross-origin refuses https->http downgrade", RedirectCrossOrigin, "http://h2/b", []string{"https://h/a"}, true},
		{"cross-origin refuses same-host downgrade", RedirectCrossOrigin, "http://h/b", []string{"https://h/a"}, true},

		// Hop bound applies wherever redirects are followed.
		{"same-origin bounds 10 hops", RedirectSameOrigin, "https://h/z",
			[]string{"https://h/0", "https://h/1", "https://h/2", "https://h/3", "https://h/4",
				"https://h/5", "https://h/6", "https://h/7", "https://h/8", "https://h/9"}, true},
		{"cross-origin bounds 10 hops", RedirectCrossOrigin, "https://h/z",
			[]string{"https://a/0", "https://a/1", "https://a/2", "https://a/3", "https://a/4",
				"https://a/5", "https://a/6", "https://a/7", "https://a/8", "https://a/9"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			check := redirectPolicy(tc.policy)
			err := check(mkReq(t, tc.to), chain(t, tc.via...))
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("err = %v; want ErrInvalidConfig", err)
				}
			} else if err != nil {
				t.Fatalf("err = %v; want nil (allowed)", err)
			}
		})
	}
}

// redirectFixture stands up B (serves payload) and A (302 -> B/file). A and B
// listen on different ports, so A->B is a genuine cross-origin redirect.
func redirectFixture(t *testing.T, payload []byte) (aURL string) {
	t.Helper()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srvB.Close)
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvB.URL+"/file", http.StatusFound)
	}))
	t.Cleanup(srvA.Close)
	return srvA.URL + "/file"
}

// TestHTTPFetch_RedirectPolicy_EndToEnd proves the policy is actually wired into
// the default client: a cross-origin 302 is refused under the default
// (RedirectSameOrigin) and followed under RedirectCrossOrigin, while the sha256
// pin still governs the bytes.
func TestHTTPFetch_RedirectPolicy_EndToEnd(t *testing.T) {
	payload := []byte("payload behind a cross-origin redirect")
	aURL := redirectFixture(t, payload)

	// Default policy refuses the cross-origin hop.
	destDefault := filepath.Join(t.TempDir(), "f")
	recordDestUnder(t, destDefault)
	srcDefault, err := NewHTTP(HTTPConfig{URL: aURL})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if _, err := srcDefault.Fetch(context.Background(), destDefault); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("default policy Fetch err = %v; want ErrInvalidConfig", err)
	}

	// RedirectCrossOrigin follows the hop and writes the payload.
	destCross := filepath.Join(t.TempDir(), "f")
	recordDestUnder(t, destCross)
	srcCross, err := NewHTTP(HTTPConfig{URL: aURL, Redirect: RedirectCrossOrigin})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	res, err := srcCross.Fetch(context.Background(), destCross)
	if err != nil {
		t.Fatalf("cross-origin Fetch: %v", err)
	}
	if got, _ := os.ReadFile(destCross); string(got) != string(payload) {
		t.Fatalf("dest = %q; want %q", got, payload)
	}
	if !res.Changed {
		t.Fatalf("Result = %+v; want Changed", res)
	}

	// The pin still governs: wrong checksum fails closed even across the redirect.
	destPin := filepath.Join(t.TempDir(), "f")
	recordDestUnder(t, destPin)
	srcPin, err := NewHTTP(HTTPConfig{URL: aURL, Redirect: RedirectCrossOrigin, ChecksumSHA256: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if _, err := srcPin.Fetch(context.Background(), destPin); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong-pin Fetch err = %v; want ErrIntegrity", err)
	}
}

// TestFetchBytes_RedirectPolicy proves FetchBytes honours the same policy field
// (both entry points share newHTTPSource).
func TestFetchBytes_RedirectPolicy(t *testing.T) {
	payload := []byte("bytes behind a redirect")
	aURL := redirectFixture(t, payload)

	if _, err := FetchBytes(context.Background(), HTTPConfig{URL: aURL}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("default FetchBytes err = %v; want ErrInvalidConfig", err)
	}

	got, err := FetchBytes(context.Background(), HTTPConfig{URL: aURL, Redirect: RedirectCrossOrigin})
	if err != nil {
		t.Fatalf("cross-origin FetchBytes: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("FetchBytes = %q; want %q", got, payload)
	}
}
