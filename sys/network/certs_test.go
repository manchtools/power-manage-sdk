package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

func eapProfile(t *testing.T, certDir string) Profile {
	t.Helper()
	return Profile{
		Name: "pm-wifi-eap", SSID: "SecureNet", AuthType: AuthEAPTLS,
		Identity: "device@corp.example.com", CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: certDir, AutoConnect: true,
	}
}

func TestWriteCerts(t *testing.T) {
	dir := t.TempDir()
	if err := writeCerts(eapProfile(t, dir)); err != nil {
		t.Fatalf("writeCerts: %v", err)
	}
	want := map[string]struct {
		content string
		mode    os.FileMode
	}{
		"ca.pem":         {realCACert, 0o640},
		"client.pem":     {realClientCert, 0o640},
		"client-key.pem": {realPEMKey, 0o600},
	}
	for name, w := range want {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if string(data) != w.content {
			t.Errorf("%s content = %q, want %q", name, data, w.content)
		}
		info, _ := os.Stat(filepath.Join(dir, name))
		if info.Mode().Perm() != w.mode {
			t.Errorf("%s mode = %o, want %o", name, info.Mode().Perm(), w.mode)
		}
	}
}

func TestWriteCerts_SkipsEmpty(t *testing.T) {
	dir := t.TempDir()
	p := Profile{CertDir: dir, CACert: realCACert} // no client cert/key
	if err := writeCerts(p); err != nil {
		t.Fatalf("writeCerts: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		t.Errorf("ca.pem should exist: %v", err)
	}
	for _, name := range []string{"client.pem", "client-key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should not exist when its content is empty", name)
		}
	}
}

func swapCertSeams(t *testing.T) {
	t.Helper()
	om, ow, orf, orn, ost, ora, orm := mkdirAll, writeFile, readFile, renameFile, statFile, removeAll, removeFile
	t.Cleanup(func() {
		mkdirAll, writeFile, readFile, renameFile, statFile, removeAll, removeFile = om, ow, orf, orn, ost, ora, orm
	})
}

func TestWriteCerts_MkdirFails(t *testing.T) {
	swapCertSeams(t)
	mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
	if err := writeCerts(eapProfile(t, "/x")); err == nil || !strings.Contains(err.Error(), "create cert directory") {
		t.Errorf("err = %v, want a wrapped mkdir failure", err)
	}
}

func TestWriteCerts_WriteFails(t *testing.T) {
	swapCertSeams(t)
	mkdirAll = func(string, os.FileMode) error { return nil }
	writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	if err := writeCerts(eapProfile(t, "/x")); err == nil || !strings.Contains(err.Error(), "write ca.pem") {
		t.Errorf("err = %v, want a wrapped write failure", err)
	}
}

func TestCertsChanged(t *testing.T) {
	dir := t.TempDir()
	if err := writeCerts(eapProfile(t, dir)); err != nil {
		t.Fatal(err)
	}
	if certsChanged(eapProfile(t, dir)) {
		t.Error("certsChanged = true when on-disk content matches")
	}
	// Rotate the client key on disk content → changed.
	rotated := eapProfile(t, dir)
	rotated.ClientKey = exec.NewMultilineSecret("-----BEGIN PRIVATE KEY-----\nDIFFERENT\n-----END PRIVATE KEY-----\n")
	if !certsChanged(rotated) {
		t.Error("certsChanged = false after the private key rotated")
	}
	// Missing file (empty dir) with non-empty desired → changed.
	if !certsChanged(eapProfile(t, t.TempDir())) {
		t.Error("certsChanged = false when the cert files are absent")
	}
	// Empty desired content is skipped (not treated as changed).
	if certsChanged(Profile{CertDir: dir}) {
		t.Error("certsChanged = true when all desired contents are empty")
	}
}

func TestRemoveCerts(t *testing.T) {
	dir := t.TempDir()
	if err := writeCerts(eapProfile(t, dir)); err != nil {
		t.Fatal(err)
	}
	if err := removeCerts(dir); err != nil {
		t.Fatalf("removeCerts(present) = %v, want nil", err)
	}
	for _, name := range []string{"ca.pem", "client.pem", "client-key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should be gone after removeCerts", name)
		}
	}
	// An already-absent file is not a failure (idempotent cleanup).
	if err := removeCerts(dir); err != nil {
		t.Errorf("removeCerts(already gone) = %v, want nil", err)
	}
}

// A removal failure on the private key must surface, not vanish: a client-key.pem
// that can't be deleted is key material left on disk the caller has to know about.
func TestRemoveCerts_SurfacesRemovalFailure(t *testing.T) {
	swapCertSeams(t)
	removeFile = func(string) error { return errors.New("read-only fs") }
	err := removeCerts("/etc/nm/certs")
	if err == nil {
		t.Fatal("removeCerts with a failing remove = nil, want the failure surfaced")
	}
	if !strings.Contains(err.Error(), "ca.pem") {
		t.Errorf("err = %v, want the first failing file named", err)
	}
}

// --- stagedModify failure branches (rename-rollback), driven through seams ---

func TestStagedModify_WriteCertsFails(t *testing.T) {
	swapCertSeams(t)
	mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
	m := &networkManager{r: &recordingRunner{}}
	if _, err := m.stagedModify(context.Background(), eapProfile(t, "/var/lib/x"), nil); err == nil ||
		!strings.Contains(err.Error(), "write staged certificates") {
		t.Errorf("err = %v, want a wrapped staged-write failure", err)
	}
}

func TestStagedModify_NmcliModFails(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "eap")
	r := &recordingRunner{}
	r.push(exec.Result{ExitCode: 1, Stderr: "Error: mod failed"}, nil)
	m := &networkManager{r: r}
	if _, err := m.stagedModify(context.Background(), eapProfile(t, certDir), nil); err == nil ||
		!strings.Contains(err.Error(), "modify connection") {
		t.Errorf("err = %v, want a wrapped modify failure", err)
	}
	// Staged dir cleaned up by the deferred removeAll.
	if _, err := os.Stat(certDir + ".tmp"); !os.IsNotExist(err) {
		t.Error(".tmp staging dir should be cleaned up after a modify failure")
	}
}

func TestStagedModify_BackupRenameFails(t *testing.T) {
	swapCertSeams(t)
	certDir := filepath.Join(t.TempDir(), "eap")
	if err := os.MkdirAll(certDir, 0o750); err != nil { // live dir exists
		t.Fatal(err)
	}
	renameFile = func(src, dst string) error {
		if src == certDir { // the backup live → .old
			return errors.New("backup denied")
		}
		return os.Rename(src, dst)
	}
	m := &networkManager{r: &recordingRunner{}}
	if _, err := m.stagedModify(context.Background(), eapProfile(t, certDir), nil); err == nil ||
		!strings.Contains(err.Error(), "backup old cert directory") {
		t.Errorf("err = %v, want a wrapped backup failure", err)
	}
}

func TestStagedModify_InstallRenameFails_NoLive(t *testing.T) {
	swapCertSeams(t)
	certDir := filepath.Join(t.TempDir(), "eap") // no live dir
	renameFile = func(src, dst string) error {
		if dst == certDir {
			return errors.New("install denied")
		}
		return os.Rename(src, dst)
	}
	m := &networkManager{r: &recordingRunner{}}
	_, err := m.stagedModify(context.Background(), eapProfile(t, certDir), nil)
	if err == nil || !strings.Contains(err.Error(), "install staged certs") ||
		strings.Contains(err.Error(), "rollback") {
		t.Errorf("err = %v, want install failure with no rollback (nothing to restore)", err)
	}
}

func TestStagedModify_InstallRenameFails_RollbackOK(t *testing.T) {
	swapCertSeams(t)
	certDir := filepath.Join(t.TempDir(), "eap")
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(certDir, "marker"), []byte("live"), 0o600)
	tmpDir := certDir + ".tmp"
	renameFile = func(src, dst string) error {
		if src == tmpDir && dst == certDir { // install fails
			return errors.New("install denied")
		}
		return os.Rename(src, dst) // backup + rollback succeed
	}
	m := &networkManager{r: &recordingRunner{}}
	_, err := m.stagedModify(context.Background(), eapProfile(t, certDir), nil)
	if err == nil || !strings.Contains(err.Error(), "install staged certs") ||
		strings.Contains(err.Error(), "rollback also failed") {
		t.Errorf("err = %v, want install failure with successful rollback", err)
	}
	// The live dir was restored (marker back in place).
	if _, serr := os.Stat(filepath.Join(certDir, "marker")); serr != nil {
		t.Errorf("live cert dir not restored after rollback: %v", serr)
	}
}

func TestStagedModify_InstallRenameFails_RollbackAlsoFails(t *testing.T) {
	swapCertSeams(t)
	certDir := filepath.Join(t.TempDir(), "eap")
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		t.Fatal(err)
	}
	tmpDir := certDir + ".tmp"
	oldDir := certDir + ".old"
	renameFile = func(src, dst string) error {
		if src == tmpDir && dst == certDir {
			return errors.New("install denied")
		}
		if src == oldDir && dst == certDir {
			return errors.New("rollback denied")
		}
		return os.Rename(src, dst)
	}
	m := &networkManager{r: &recordingRunner{}}
	_, err := m.stagedModify(context.Background(), eapProfile(t, certDir), nil)
	if err == nil || !strings.Contains(err.Error(), "rollback also failed") {
		t.Errorf("err = %v, want the double-failure (install + rollback) message", err)
	}
}

// New certs install fine, but the cleanup of the .old backup directory — which
// holds the PREVIOUS private key — fails. That must surface (changed still true),
// not be silently dropped: a stale private key left on disk is the caller's
// concern.
func TestStagedModify_OldCertCleanupFailureSurfaces(t *testing.T) {
	swapCertSeams(t)
	certDir := filepath.Join(t.TempDir(), "eap")
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		t.Fatal(err)
	}
	oldDir := certDir + ".old"
	removeAll = func(p string) error {
		if p == oldDir {
			return errors.New("read-only fs")
		}
		return os.RemoveAll(p)
	}
	m := &networkManager{r: &recordingRunner{}}
	changed, err := m.stagedModify(context.Background(), eapProfile(t, certDir), nil)
	if !changed {
		t.Error("changed = false, want true (the new certs are installed and live)")
	}
	if err == nil || !strings.Contains(err.Error(), "old cert directory") {
		t.Errorf("err = %v, want the stale-private-key cleanup failure surfaced", err)
	}
}

func TestSafeRemoveCertDir_StatNonNotExistError(t *testing.T) {
	swapCertSeams(t)
	_, certBase := redirectDirs(t)
	statFile = func(string) (os.FileInfo, error) { return nil, errors.New("permission denied") }
	if err := safeRemoveCertDir(filepath.Join(certBase, "x")); err == nil ||
		!strings.Contains(err.Error(), "stat cert directory") {
		t.Errorf("err = %v, want a wrapped non-IsNotExist stat failure", err)
	}
}

func TestSafeRemoveCertDir_AbsError(t *testing.T) {
	swapResolveSeams(t)
	absPath = func(string) (string, error) { return "", errors.New("getwd failed") }
	if err := safeRemoveCertDir("/whatever"); err == nil ||
		!strings.Contains(err.Error(), "resolve cert directory") {
		t.Errorf("err = %v, want a wrapped Abs failure", err)
	}
}

func TestSafeRemoveCertDir_RemoveAllError(t *testing.T) {
	swapCertSeams(t)
	_, certBase := redirectDirs(t)
	dir := filepath.Join(certBase, "x")
	os.MkdirAll(dir, 0o750)
	removeAll = func(string) error { return errors.New("remove failed") }
	if err := safeRemoveCertDir(dir); err == nil {
		t.Error("safeRemoveCertDir should surface a removeAll failure")
	}
}
