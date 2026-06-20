package network

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

func TestBuildPSKKeyfile(t *testing.T) {
	body := string(buildPSKKeyfile(Profile{
		Name:        "pm-wifi-abc123",
		SSID:        "CorpNet",
		AuthType:    AuthPSK,
		PSK:         mustSecret(t, "hunter2"),
		AutoConnect: true,
		Hidden:      true,
		Priority:    10,
	}))
	for _, want := range []string{
		"[connection]", "id=pm-wifi-abc123", "type=wifi",
		"autoconnect=true", "autoconnect-priority=10",
		"[wifi]", "ssid=CorpNet", "hidden=true",
		"[wifi-security]", "key-mgmt=wpa-psk", "psk=hunter2",
		"[ipv4]", "method=auto", "[ipv6]",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("keyfile body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "[802-1x]") {
		t.Errorf("PSK keyfile must not contain an [802-1x] section:\n%s", body)
	}
}

func TestBuildPSKKeyfile_AutoConnectFalseNoHidden(t *testing.T) {
	body := string(buildPSKKeyfile(Profile{
		Name: "pm-wifi-2", SSID: "OpenNet", AuthType: AuthPSK, PSK: mustSecret(t, "valid-wpa2-psk"),
	}))
	if !strings.Contains(body, "autoconnect=false") {
		t.Errorf("expected autoconnect=false:\n%s", body)
	}
	if strings.Contains(body, "hidden=") {
		t.Errorf("hidden= should be absent (NM default) when Hidden is false:\n%s", body)
	}
}

func TestKeyfilePath_StripsSeparators(t *testing.T) {
	got := keyfilePath("../escape/attempt")
	if filepath.Dir(got) != nmKeyfileDir {
		t.Errorf("keyfile escaped nmKeyfileDir: %q", got)
	}
	if strings.ContainsRune(filepath.Base(got), filepath.Separator) {
		t.Errorf("basename must not contain a separator: %q", filepath.Base(got))
	}
	if !strings.HasSuffix(got, ".nmconnection") {
		t.Errorf("path must end with .nmconnection: %q", got)
	}
}

func TestWriteKeyfile_AtomicMode0600(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pm-wifi.nmconnection")
	content := []byte("[connection]\nid=pm-wifi\n")
	if err := writeKeyfile(target, content); err != nil {
		t.Fatalf("writeKeyfile: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(content) {
		t.Errorf("body = %q, want %q", got, content)
	}
	// No temp leftovers.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pm-keyfile-") {
			t.Errorf("temp keyfile not cleaned up: %s", e.Name())
		}
	}
}

// --- fault injection via seams ---

// fakeHandle is a keyfileHandle that fails on a chosen step.
type fakeHandle struct {
	name                            string
	failWrite, failChmod, failClose bool
	closed                          bool
}

func (f *fakeHandle) Name() string { return f.name }
func (f *fakeHandle) Write(b []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("disk full")
	}
	return len(b), nil
}
func (f *fakeHandle) Chmod(os.FileMode) error {
	if f.failChmod {
		return errors.New("chmod denied")
	}
	return nil
}
func (f *fakeHandle) Close() error {
	f.closed = true
	if f.failClose {
		return errors.New("close failed")
	}
	return nil
}

func swapSeams(t *testing.T) {
	t.Helper()
	om, oc, or_, orm := mkdirAll, createTemp, renameFile, removeFile
	t.Cleanup(func() { mkdirAll, createTemp, renameFile, removeFile = om, oc, or_, orm })
}

func TestWriteKeyfile_MkdirFails(t *testing.T) {
	swapSeams(t)
	mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
	if err := writeKeyfile("/x/y.nmconnection", []byte("z")); err == nil || !strings.Contains(err.Error(), "create keyfile dir") {
		t.Errorf("err = %v, want a wrapped mkdir failure", err)
	}
}

func TestWriteKeyfile_CreateTempFails(t *testing.T) {
	swapSeams(t)
	mkdirAll = func(string, os.FileMode) error { return nil }
	createTemp = func(string, string) (keyfileHandle, error) { return nil, errors.New("no temp") }
	if err := writeKeyfile("/x/y.nmconnection", []byte("z")); err == nil || !strings.Contains(err.Error(), "create temp keyfile") {
		t.Errorf("err = %v, want a wrapped create-temp failure", err)
	}
}

func TestWriteKeyfile_WriteChmodCloseRenameFail(t *testing.T) {
	cases := []struct {
		name    string
		handle  *fakeHandle
		rename  func(string, string) error
		wantMsg string
	}{
		{"write", &fakeHandle{name: "/tmp/seam.tmp", failWrite: true}, os.Rename, "write keyfile"},
		{"chmod", &fakeHandle{name: "/tmp/seam.tmp", failChmod: true}, os.Rename, "chmod keyfile"},
		{"close", &fakeHandle{name: "/tmp/seam.tmp", failClose: true}, os.Rename, "close keyfile"},
		{"rename", &fakeHandle{name: "/tmp/seam.tmp"}, func(string, string) error { return errors.New("rename denied") }, "rename keyfile"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			swapSeams(t)
			var removed string
			mkdirAll = func(string, os.FileMode) error { return nil }
			createTemp = func(string, string) (keyfileHandle, error) { return c.handle, nil }
			renameFile = c.rename
			removeFile = func(p string) error { removed = p; return nil }

			err := writeKeyfile("/etc/nm/y.nmconnection", []byte("z"))
			if err == nil || !strings.Contains(err.Error(), c.wantMsg) {
				t.Fatalf("err = %v, want a wrapped %q failure", err, c.wantMsg)
			}
			// Every failure must scrub the temp file (no plaintext residue).
			if removed != c.handle.name {
				t.Errorf("temp %q not removed on %s failure (removed %q)", c.handle.name, c.name, removed)
			}
		})
	}
}

// Belt-and-braces: a PSK with a newline can never be constructed, so it can never
// inject extra keyfile lines.
func TestPSKSecret_RejectsNewlineAtConstruction(t *testing.T) {
	if _, err := exec.NewSecret("line1\nkey-mgmt=none"); err == nil {
		t.Error("NewSecret accepted a newline-bearing PSK — keyfile injection would be possible")
	}
}
