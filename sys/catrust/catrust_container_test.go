//go:build container

// Container-based real-execution test for the CA trust-store flow. The fake-
// runner unit tests assert the emitted refresh argv and the file written to the
// anchors dir; this runs the REAL refresh tool (update-ca-certificates on
// Debian/SUSE, update-ca-trust on Fedora/EL/Arch) and proves the installed CA
// actually becomes trusted by — and is distrusted from — the system store. This
// is the security-relevant round-trip: a trusted CA can MITM any TLS connection.
//
// Distro-aware: Detect() picks the backend this host provides, so the test runs
// on EVERY supported distro with its native trust mechanism. Trust is verified
// with `openssl verify` rather than a hardcoded bundle path — a self-signed root
// verifies OK iff it is in the system trust store, and that probe is identical
// across distros whose consolidated bundle paths all differ.
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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

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

// caTrusted reports whether the system trust store currently trusts the CA in
// pemPath. It uses `openssl verify`, the portable, bundle-path-independent probe:
// a self-signed root verifies OK iff it is in the system trust store. This works
// uniformly across the Debian/SUSE update-ca-certificates and the Fedora/EL/Arch
// update-ca-trust flows, whose consolidated bundle locations all differ.
func caTrusted(pemPath string) bool {
	out, err := osexec.Command("openssl", "verify", pemPath).CombinedOutput()
	return err == nil && strings.Contains(string(out), ": OK")
}

// TestInstallRemove_RealTrustStore_Container drives the REAL trust-store flow on
// whatever backend this distro provides, proving an installed CA actually becomes
// trusted and that Remove distrusts it.
func TestInstallRemove_RealTrustStore_Container(t *testing.T) {
	if _, err := osexec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH — cannot probe the system trust store")
	}
	backends := Detect(context.Background())
	if len(backends) == 0 {
		t.Skip("no CA trust-store backend detected on this host")
	}
	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}

	for _, backend := range backends {
		t.Run(backend.String(), func(t *testing.T) {
			m, err := New(backend, r)
			if err != nil {
				t.Fatalf("New(%v): %v", backend, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			const name = "pm-container-test-ca"
			const cn = "pm container test root"
			pemBytes := selfSignedCA(t, cn)
			pemPath := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(pemPath, pemBytes, 0o644); err != nil {
				t.Fatalf("write CA pem: %v", err)
			}
			t.Cleanup(func() { _ = m.Remove(context.Background(), name) })

			if caTrusted(pemPath) {
				t.Fatalf("CA %q is already trusted before Install — dirty test environment", cn)
			}
			// Install → the CA must actually become trusted by the real system store.
			if err := m.Install(ctx, name, pemBytes); err != nil {
				t.Fatalf("Install: %v", err)
			}
			if !caTrusted(pemPath) {
				t.Fatalf("after Install via %v, CA %q is NOT trusted by the real system store", backend, cn)
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
			// Remove → distrust must take effect.
			if err := m.Remove(ctx, name); err != nil {
				t.Fatalf("Remove: %v", err)
			}
			if caTrusted(pemPath) {
				t.Errorf("after Remove via %v, CA %q is STILL trusted — distrust failed", backend, cn)
			}
		})
	}
}
