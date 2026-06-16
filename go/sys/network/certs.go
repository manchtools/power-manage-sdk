package network

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeCerts writes the EAP-TLS certificate files to the profile's CertDir. The
// CA and client certificates are not credentials; the private key is, so it is
// written 0600 and is the only file whose content comes from a Secret —
// p.ClientKey.Reveal() here is the sanctioned client-key sink.
func writeCerts(p Profile) error {
	if err := mkdirAll(p.CertDir, 0o750); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}
	files := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{"ca.pem", p.CACert, 0o640},
		{"client.pem", p.ClientCert, 0o640},
		{"client-key.pem", p.ClientKey.Reveal(), 0o600},
	}
	for _, f := range files {
		if f.content == "" {
			continue
		}
		path := filepath.Join(p.CertDir, f.name)
		if err := writeFile(path, []byte(f.content), f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return nil
}

// removeCerts removes the certificate files written by writeCerts. Best-effort —
// errors are ignored since this only runs as cleanup after a failed create.
func removeCerts(certDir string) {
	for _, name := range []string{"ca.pem", "client.pem", "client-key.pem"} {
		removeFile(filepath.Join(certDir, name))
	}
}

// certsChanged reports whether any desired PEM content differs from the file
// currently installed at the corresponding path under p.CertDir. A missing or
// unreadable file (with non-empty desired content) counts as changed so the
// writer runs. p.ClientKey.Reveal() here compares the on-disk private key against
// the desired one — the same sanctioned client-key sink as writeCerts.
func certsChanged(p Profile) bool {
	files := []struct {
		name    string
		content string
	}{
		{"ca.pem", p.CACert},
		{"client.pem", p.ClientCert},
		{"client-key.pem", p.ClientKey.Reveal()},
	}
	for _, f := range files {
		if f.content == "" {
			continue
		}
		existing, err := readFile(filepath.Join(p.CertDir, f.name))
		if err != nil || string(existing) != f.content {
			return true
		}
	}
	return false
}
