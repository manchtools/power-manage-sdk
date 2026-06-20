//go:build container

// Container-based real-execution test for the CA trust-store flow. The fake-
// runner unit tests assert the emitted update-ca-certificates argv and the file
// written to the anchors dir; this runs the REAL update-ca-certificates and then
// proves the installed CA actually appears in (and is removed from) the system
// trust bundle — the security-relevant round-trip, since a trusted CA can MITM
// any TLS connection. Anti-rot guard: a future update-ca-certificates that
// changes its bundle path or behaviour is caught here.
//
// Debian/CaCertificates backend only (the test image). Self-skips when
// update-ca-certificates is absent.
package catrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	osexec "os/exec"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// debianBundle is where update-ca-certificates concatenates every trusted CA.
const debianBundle = "/etc/ssl/certs/ca-certificates.crt"

// selfSignedCA returns a PEM-encoded self-signed CA certificate with the given
// CommonName, valid 2000-2100 (spans now without using the wall clock).
func selfSignedCA(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// bundleHasCN parses the real system CA bundle and reports whether any cert in
// it has the given CommonName.
func bundleHasCN(t *testing.T, cn string) bool {
	t.Helper()
	raw, err := os.ReadFile(debianBundle)
	if err != nil {
		t.Fatalf("read system bundle %s: %v", debianBundle, err)
	}
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if c.Subject.CommonName == cn {
			return true
		}
	}
	return false
}

func TestInstallRemove_RealTrustStore_Container(t *testing.T) {
	if _, err := osexec.LookPath("update-ca-certificates"); err != nil {
		t.Skip("update-ca-certificates not on PATH")
	}
	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := New(CaCertificates, r)
	if err != nil {
		t.Fatalf("New(CaCertificates): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const name = "pm-container-test-ca"
	const cn = "pm container test root"
	pemBytes := selfSignedCA(t, cn)

	t.Cleanup(func() { _ = m.Remove(context.Background(), name) })

	// Install → the CA must actually appear in the real system bundle.
	if err := m.Install(ctx, name, pemBytes); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !bundleHasCN(t, cn) {
		t.Fatalf("after Install, CA %q is NOT in the real system bundle %s — not actually trusted", cn, debianBundle)
	}
	anchors, err := m.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, a := range anchors {
		if a.Name == name {
			found = true
		}
	}
	if !found {
		t.Errorf("List does not report the installed anchor %q: %+v", name, anchors)
	}

	// Remove → the CA must be gone from the real bundle (distrust took effect).
	if err := m.Remove(ctx, name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if bundleHasCN(t, cn) {
		t.Errorf("after Remove, CA %q is STILL in the real system bundle %s — distrust failed", cn, debianBundle)
	}
}
