// Package cryptotest provides shared X.509 test fixtures so the sdk and agent
// test suites do not each re-implement ECDSA P-256 certificate construction
// (WS16b DRY). It is a regular (non-_test) package so it can be imported across
// packages and repos; it therefore deliberately uses FIXED validity bounds
// rather than time.Now() — the module's clock seam forbids time.Now() outside
// _test files, and a wide fixed window is "valid now" for any realistic test
// run while staying within the ASN.1 GeneralizedTime range.
package cryptotest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Fixed validity window: valid for any realistic test run, comfortably within
// ASN.1 range. No time.Now() so this importable package stays within the
// module clock seam.
var (
	notBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
)

// serialCounter hands out unique-per-process serial numbers so multiple certs
// generated in one test run don't collide (the previous per-site builders used
// time.Now().UnixNano(), which the clock seam forbids here).
var serialCounter atomic.Int64

func nextSerial() *big.Int { return big.NewInt(serialCounter.Add(1)) }

// GenCA returns a self-signed test CA: its PEM-encoded certificate, its private
// key, and the parsed certificate (for signing leaves / building pools).
func GenCA(t testing.TB, commonName string) (caPEM []byte, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, cert
}

// CAPEM is a convenience for tests that only need a fresh CA certificate blob.
func CAPEM(t testing.TB, commonName string) []byte {
	t.Helper()
	pemBytes, _, _ := GenCA(t, commonName)
	return pemBytes
}

// GenSubCA returns a sub-CA certificate PEM signed by parent/parentKey.
func GenSubCA(t testing.TB, commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("subca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create subca: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// GenLeaf issues a leaf certificate (server or client) signed by ca/caKey and
// returns the PEM-encoded certificate and key. Server leaves carry localhost
// SANs (127.0.0.1, ::1, localhost) so they work for httptest TLS servers.
func GenLeaf(t testing.TB, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, server bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// EncodeCertPEM PEM-encodes an already-parsed certificate.
func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
