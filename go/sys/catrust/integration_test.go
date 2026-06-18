//go:build integration

package catrust_test

import (
	"bytes"
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

	"github.com/manchtools/power-manage/sdk/go/sys/catrust"
	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// bundlePath is the consolidated trust bundle each backend rebuilds — where an
// installed anchor must actually appear for clients to trust it.
var bundlePath = map[catrust.Backend]string{
	catrust.CaCertificates: "/etc/ssl/certs/ca-certificates.crt",
	catrust.P11Kit:         "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
}

// genCA returns a self-signed CA as (PEM, DER) plus the cert's parsed Subject
// DN string so the test can match both the exact certificate inside the system
// bundle and the Subject/Issuer reported by List. The CA is self-signed, so its
// Issuer equals its Subject.
func genCA(t *testing.T) (pemBytes, der []byte, subject string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 5280 §5.1.2.2: serial numbers should be large random values, not
	// derived from a clock (which can collide). 128 random bits is conventional.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "PM Integration Test CA", Organization: []string{"power-manage-test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der, cert.Subject.String()
}

// bundleContainsDER reports whether the consolidated bundle holds a cert with
// the exact DER (resilient to PEM re-encoding/whitespace).
func bundleContainsDER(t *testing.T, path string, der []byte) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle %s: %v", path, err)
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return false
		}
		if block.Type == "CERTIFICATE" && bytes.Equal(block.Bytes, der) {
			return true
		}
	}
}

func integrationRunner(t *testing.T) pmexec.Runner {
	t.Helper()
	backend := pmexec.Direct
	if os.Geteuid() != 0 {
		if _, err := osexec.LookPath("sudo"); err != nil {
			t.Skip("not root and no sudo; cannot write trust anchors")
		}
		if err := osexec.Command("sudo", "-n", "true").Run(); err != nil {
			t.Skipf("sudo present but non-interactive escalation unavailable: %v", err)
		}
		backend = pmexec.Sudo
	}
	r, err := pmexec.NewRunner(backend)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

// TestRoundTrip_Integration is the real end-to-end test: in a disposable
// container, install a freshly-generated CA, prove it lands in the system trust
// bundle and List, then remove it and prove it's gone. Runs whichever backend
// the container ships (CaCertificates on Debian, P11Kit on Fedora).
func TestRoundTrip_Integration(t *testing.T) {
	backends := catrust.Detect(context.Background())
	if len(backends) == 0 {
		t.Skip("no CA-trust backend on PATH")
	}
	r := integrationRunner(t)
	ctx := context.Background()

	for _, b := range backends {
		t.Run(b.String(), func(t *testing.T) {
			m, err := catrust.New(b, r)
			if err != nil {
				t.Fatalf("New(%v): %v", b, err)
			}
			const name = "pm-integration-test-ca"
			pemBytes, der, subject := genCA(t)
			t.Cleanup(func() { _ = m.Remove(ctx, name) })

			if err := m.Install(ctx, name, pemBytes); err != nil {
				t.Fatalf("Install: %v", err)
			}

			// List must report it.
			anchors, err := m.List(ctx)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			found := false
			for _, a := range anchors {
				if a.Name == name {
					found = true
					// Self-signed: Subject and Issuer both equal the CA's subject.
					if a.Subject != subject {
						t.Errorf("anchor Subject = %q, want %q", a.Subject, subject)
					}
					if a.Issuer != subject {
						t.Errorf("anchor Issuer = %q, want %q (self-signed)", a.Issuer, subject)
					}
				}
			}
			if !found {
				t.Errorf("List does not show the installed anchor %q: %+v", name, anchors)
			}

			// The real proof: the CA is now in the consolidated system bundle.
			if bp := bundlePath[b]; bp != "" {
				if !bundleContainsDER(t, bp, der) {
					t.Errorf("installed CA not present in system bundle %s", bp)
				}
			}

			// Remove and prove it's gone from both List and the bundle.
			if err := m.Remove(ctx, name); err != nil {
				t.Fatalf("Remove: %v", err)
			}
			anchors, err = m.List(ctx)
			if err != nil {
				t.Fatalf("List after remove: %v", err)
			}
			for _, a := range anchors {
				if a.Name == name {
					t.Errorf("anchor %q still listed after Remove", name)
				}
			}
			if bp := bundlePath[b]; bp != "" {
				if bundleContainsDER(t, bp, der) {
					t.Errorf("CA still in system bundle %s after Remove", bp)
				}
			}
		})
	}
}
