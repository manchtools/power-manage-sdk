package catrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
	sdkfs "github.com/manchtools/power-manage-sdk/sys/fs"
)

// genCert builds a self-signed cert PEM with the given CA flag and validity
// window — the fixture for the validation matrix and the List parse.
func genCert(t *testing.T, cn string, isCA bool, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func validCAPEM(t *testing.T) []byte {
	return genCert(t, "ACME Root", true, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// fakeFS records WriteFile/Remove calls and replays scripted errors.
type fakeFS struct {
	writes    []fakeWrite
	removed   []string
	writeErr  error
	removeErr error
}
type fakeWrite struct {
	path string
	data []byte
	opts sdkfs.WriteOptions
}

func (f *fakeFS) WriteFile(_ context.Context, path string, data []byte, opts sdkfs.WriteOptions) error {
	f.writes = append(f.writes, fakeWrite{path, data, opts})
	return f.writeErr
}
func (f *fakeFS) Remove(_ context.Context, path string) error {
	f.removed = append(f.removed, path)
	return f.removeErr
}

func withFakeFS(t *testing.T, ff *fakeFS) {
	t.Helper()
	prev := newFS
	t.Cleanup(func() { newFS = prev })
	newFS = func(exec.Runner) (fsManager, error) { return ff, nil }
}

func newMgr(t *testing.T, b Backend, ff *fakeFS) (*manager, *exectest.FakeRunner) {
	t.Helper()
	withFakeFS(t, ff)
	r := exectest.New(exec.Direct)
	m, err := New(b, r)
	if err != nil {
		t.Fatalf("New(%v): %v", b, err)
	}
	return m.(*manager), r
}

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(CaCertificates, nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	for _, b := range []Backend{0, Backend(-1), Backend(99)} {
		if _, err := New(b, exectest.New(exec.Direct)); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) err = %v, want ErrUnknownBackend", b, err)
		}
	}
}

func TestNew_Backends(t *testing.T) {
	withFakeFS(t, &fakeFS{})
	for _, b := range []Backend{CaCertificates, P11Kit} {
		if _, err := New(b, exectest.New(exec.Direct)); err != nil {
			t.Errorf("New(%v): %v", b, err)
		}
	}
}

// TestNew_UsesRealFS exercises the production newFS closure (fs.New) — the other
// tests stub it.
func TestNew_UsesRealFS(t *testing.T) {
	if _, err := New(CaCertificates, exectest.New(exec.Direct)); err != nil {
		t.Errorf("New with the real fs.Manager: %v", err)
	}
}

func TestNew_PropagatesFSError(t *testing.T) {
	prev := newFS
	t.Cleanup(func() { newFS = prev })
	sentinel := errors.New("fs boom")
	newFS = func(exec.Runner) (fsManager, error) { return nil, sentinel }
	if _, err := New(CaCertificates, exectest.New(exec.Direct)); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the fs error", err)
	}
}

func TestBackendString(t *testing.T) {
	cases := map[Backend]string{CaCertificates: "ca-certificates", P11Kit: "p11-kit", Backend(0): "Backend(0)"}
	for b, want := range cases {
		if got := b.String(); got != want {
			t.Errorf("Backend(%d).String() = %q, want %q", int(b), got, want)
		}
	}
}

func TestValidateName(t *testing.T) {
	cases := map[string]bool{
		"acme-corp-root": true, "ca_1.crt": true, "A": true,
		"": false, "-x": false, "a/b": false, "../etc/x": false, "a..b": false,
		strings.Repeat("a", 64): false,
	}
	for name, valid := range cases {
		err := validateName(name)
		if valid != (err == nil) {
			t.Errorf("validateName(%q): err=%v wantValid=%v", name, err, valid)
		}
	}
}

func TestValidateCACert(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		pem     []byte
		wantErr bool
	}{
		{"valid CA", genCert(t, "CA", true, now.Add(-time.Hour), now.Add(time.Hour)), false},
		{"not a CA (leaf)", genCert(t, "leaf", false, now.Add(-time.Hour), now.Add(time.Hour)), true},
		{"expired", genCert(t, "old", true, now.Add(-48*time.Hour), now.Add(-time.Hour)), true},
		{"not yet valid", genCert(t, "future", true, now.Add(time.Hour), now.Add(48*time.Hour)), true},
		{"garbage", []byte("not a pem"), true},
		{"wrong pem type", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), true},
		{"corrupt der", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCACert(tc.pem)
			if tc.wantErr && !errors.Is(err, ErrInvalidCert) {
				t.Errorf("validateCACert = %v, want ErrInvalidCert", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateCACert = %v, want nil", err)
			}
		})
	}
}

func TestInstall_CaCertificates(t *testing.T) {
	ff := &fakeFS{}
	m, r := newMgr(t, CaCertificates, ff)
	r.Push(exec.Result{}, nil) // update-ca-certificates
	cert := validCAPEM(t)
	if err := m.Install(context.Background(), "acme-root", cert); err != nil {
		t.Fatal(err)
	}
	if len(ff.writes) != 1 || ff.writes[0].path != "/usr/local/share/ca-certificates/acme-root.crt" {
		t.Fatalf("writes = %v", ff.writes)
	}
	if string(ff.writes[0].data) != string(cert) || ff.writes[0].opts.Owner != "root" {
		t.Errorf("write data/opts wrong: %+v", ff.writes[0].opts)
	}
	c := r.Calls()[0]
	if strings.Join(append([]string{c.Name}, c.Args...), " ") != "update-ca-certificates" || !c.Escalate {
		t.Errorf("refresh = %v (escalate=%v), want escalated update-ca-certificates", append([]string{c.Name}, c.Args...), c.Escalate)
	}
}

func TestInstall_P11Kit(t *testing.T) {
	ff := &fakeFS{}
	m, r := newMgr(t, P11Kit, ff)
	r.Push(exec.Result{}, nil)
	if err := m.Install(context.Background(), "acme-root", validCAPEM(t)); err != nil {
		t.Fatal(err)
	}
	if ff.writes[0].path != "/etc/pki/ca-trust/source/anchors/acme-root.crt" {
		t.Errorf("p11kit path = %q", ff.writes[0].path)
	}
	c := r.Calls()[0]
	if strings.Join(append([]string{c.Name}, c.Args...), " ") != "update-ca-trust extract" {
		t.Errorf("p11kit refresh = %v", append([]string{c.Name}, c.Args...))
	}
}

func TestInstall_Rejections(t *testing.T) {
	ff := &fakeFS{}
	m, r := newMgr(t, CaCertificates, ff)
	if err := m.Install(context.Background(), "-bad", validCAPEM(t)); !errors.Is(err, ErrInvalidName) {
		t.Errorf("bad name err = %v", err)
	}
	if err := m.Install(context.Background(), "ok", []byte("garbage")); !errors.Is(err, ErrInvalidCert) {
		t.Errorf("bad cert err = %v", err)
	}
	if len(ff.writes) != 0 || len(r.Calls()) != 0 {
		t.Error("a rejected Install must write nothing and run nothing")
	}
}

func TestInstall_WriteAndRefreshErrors(t *testing.T) {
	m, _ := newMgr(t, CaCertificates, &fakeFS{writeErr: errors.New("ro fs")})
	if err := m.Install(context.Background(), "x", validCAPEM(t)); err == nil {
		t.Error("a write failure must propagate")
	}
	ff := &fakeFS{}
	m2, r := newMgr(t, CaCertificates, ff)
	r.Push(exec.Result{ExitCode: 1, Stderr: "boom"}, nil)
	if err := m2.Install(context.Background(), "x", validCAPEM(t)); err == nil {
		t.Error("a refresh non-zero exit must propagate")
	}
	// refresh Runner error (e.g. update-ca-certificates not installed)
	ff3 := &fakeFS{}
	m3, r3 := newMgr(t, CaCertificates, ff3)
	r3.Push(exec.Result{}, errors.New("update-ca-certificates not found"))
	if err := m3.Install(context.Background(), "x", validCAPEM(t)); err == nil {
		t.Error("a refresh Runner error must propagate")
	}
}

func TestRemove_Success(t *testing.T) {
	ff := &fakeFS{}
	m, r := newMgr(t, CaCertificates, ff)
	prev := stat
	t.Cleanup(func() { stat = prev })
	stat = func(string) (os.FileInfo, error) { return nil, nil } // exists
	r.Push(exec.Result{}, nil)                                   // update-ca-certificates --fresh
	if err := m.Remove(context.Background(), "acme-root"); err != nil {
		t.Fatal(err)
	}
	if len(ff.removed) != 1 || ff.removed[0] != "/usr/local/share/ca-certificates/acme-root.crt" {
		t.Fatalf("removed = %v", ff.removed)
	}
	c := r.Calls()[0]
	if strings.Join(append([]string{c.Name}, c.Args...), " ") != "update-ca-certificates --fresh" || !c.Escalate {
		t.Errorf("remove refresh = %v", append([]string{c.Name}, c.Args...))
	}
}

func TestRemove_IdempotentWhenAbsent(t *testing.T) {
	ff := &fakeFS{}
	m, r := newMgr(t, CaCertificates, ff)
	prev := stat
	t.Cleanup(func() { stat = prev })
	stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	if err := m.Remove(context.Background(), "absent"); err != nil {
		t.Errorf("removing an absent anchor must be a no-op success, got %v", err)
	}
	if len(ff.removed) != 0 || len(r.Calls()) != 0 {
		t.Error("absent remove must do nothing")
	}
}

func TestRemove_Errors(t *testing.T) {
	prev := stat
	t.Cleanup(func() { stat = prev })

	// stat error other than not-exist
	ff := &fakeFS{}
	m, _ := newMgr(t, CaCertificates, ff)
	stat = func(string) (os.FileInfo, error) { return nil, errors.New("permission denied") }
	if err := m.Remove(context.Background(), "x"); err == nil {
		t.Error("a non-notexist stat error must propagate")
	}

	// remove error
	stat = func(string) (os.FileInfo, error) { return nil, nil } // exists
	ff2 := &fakeFS{removeErr: errors.New("rm failed")}
	m2, _ := newMgr(t, CaCertificates, ff2)
	if err := m2.Remove(context.Background(), "x"); err == nil {
		t.Error("a remove error must propagate")
	}

	// refresh error
	ff3 := &fakeFS{}
	m3, r := newMgr(t, CaCertificates, ff3)
	r.Push(exec.Result{ExitCode: 1, Stderr: "boom"}, nil)
	if err := m3.Remove(context.Background(), "x"); err == nil {
		t.Error("a refresh error must propagate")
	}

	// bad name
	m4, _ := newMgr(t, CaCertificates, &fakeFS{})
	if err := m4.Remove(context.Background(), "-bad"); !errors.Is(err, ErrInvalidName) {
		t.Errorf("bad name err = %v", err)
	}
}

// fakeDirEntry is a minimal os.DirEntry for List tests.
type fakeDirEntry struct {
	name string
	dir  bool
}

func (e fakeDirEntry) Name() string               { return e.name }
func (e fakeDirEntry) IsDir() bool                { return e.dir }
func (e fakeDirEntry) Type() fs.FileMode          { return 0 }
func (e fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestList(t *testing.T) {
	ff := &fakeFS{}
	m, _ := newMgr(t, CaCertificates, ff)
	caPEM := validCAPEM(t)

	prevRD, prevRF := readDir, readFile
	t.Cleanup(func() { readDir, readFile = prevRD, prevRF })
	readDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{
			fakeDirEntry{name: "acme-root.crt"},
			fakeDirEntry{name: "subdir", dir: true}, // skipped
			fakeDirEntry{name: "README.txt"},        // non-.crt, skipped
			fakeDirEntry{name: "corrupt.crt"},       // unparseable, skipped
		}, nil
	}
	readFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "acme-root.crt") {
			return caPEM, nil
		}
		if strings.HasSuffix(path, "corrupt.crt") {
			return []byte("not a cert"), nil
		}
		return nil, os.ErrNotExist
	}
	got, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "acme-root" || !strings.Contains(got[0].Subject, "ACME Root") {
		t.Fatalf("List = %+v, want one acme-root anchor", got)
	}
}

func TestList_MissingDirIsEmpty(t *testing.T) {
	m, _ := newMgr(t, CaCertificates, &fakeFS{})
	prev := readDir
	t.Cleanup(func() { readDir = prev })
	readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }
	got, err := m.List(context.Background())
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("List(missing dir) = (%v,%v), want empty non-nil", got, err)
	}
}

func TestList_ReadDirError(t *testing.T) {
	m, _ := newMgr(t, CaCertificates, &fakeFS{})
	prev := readDir
	t.Cleanup(func() { readDir = prev })
	readDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("permission denied") }
	if _, err := m.List(context.Background()); err == nil {
		t.Error("a non-notexist readDir error must propagate")
	}
}

// readFile-error-while-listing skips that entry (covered: corrupt.crt path
// returns ErrNotExist in TestList and is skipped).
func TestList_ReadFileErrorSkipsEntry(t *testing.T) {
	m, _ := newMgr(t, CaCertificates, &fakeFS{})
	prevRD, prevRF := readDir, readFile
	t.Cleanup(func() { readDir, readFile = prevRD, prevRF })
	readDir = func(string) ([]os.DirEntry, error) {
		return []os.DirEntry{fakeDirEntry{name: "unreadable.crt"}}, nil
	}
	readFile = func(string) ([]byte, error) { return nil, errors.New("EACCES") }
	got, err := m.List(context.Background())
	if err != nil || len(got) != 0 {
		t.Errorf("List = (%v,%v), want empty (unreadable entry skipped)", got, err)
	}
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name    string
		present map[string]bool
		want    []Backend
	}{
		{"none", map[string]bool{}, nil},
		{"debian", map[string]bool{"update-ca-certificates": true}, []Backend{CaCertificates}},
		{"fedora", map[string]bool{"update-ca-trust": true}, []Backend{P11Kit}},
		{"both", map[string]bool{"update-ca-certificates": true, "update-ca-trust": true}, []Backend{CaCertificates, P11Kit}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := lookPath
			t.Cleanup(func() { lookPath = prev })
			lookPath = func(name string) (string, error) {
				if tc.present[name] {
					return "/usr/sbin/" + name, nil
				}
				return "", errors.New("no")
			}
			got := Detect(context.Background())
			if len(got) != len(tc.want) {
				t.Fatalf("Detect = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Detect[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
