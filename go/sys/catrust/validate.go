package catrust

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ErrInvalidName is returned when an anchor name is unsafe as a filename.
var ErrInvalidName = errors.New("catrust: invalid anchor name")

// ErrInvalidCert is returned when the supplied certificate is not a usable CA.
var ErrInvalidCert = errors.New("catrust: invalid CA certificate")

// validName matches a safe anchor name: leading alphanumeric (never flag-shaped),
// then alphanumerics plus . _ -, up to 63 chars. It becomes a filename in a
// root-owned directory, so no '/' and no path traversal.
var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

// validateName rejects an unsafe anchor name.
func validateName(name string) error {
	if !validName.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("%w: %q (use [A-Za-z0-9._-], no '/' or '..')", ErrInvalidName, name)
	}
	return nil
}

// validateCACert parses certPEM and requires a well-formed CA certificate that is
// currently valid. Installing a non-CA or expired cert is virtually always a
// mistake, so it fails closed.
func validateCACert(certPEM []byte) error {
	cert, err := parseCert(certPEM)
	if err != nil {
		return err
	}
	if !cert.IsCA {
		return fmt.Errorf("%w: certificate %q is not a CA (BasicConstraints CA=false)", ErrInvalidCert, cert.Subject.CommonName)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: certificate is not valid until %s", ErrInvalidCert, cert.NotBefore.UTC())
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: certificate expired on %s", ErrInvalidCert, cert.NotAfter.UTC())
	}
	return nil
}

// parseCert decodes a single PEM CERTIFICATE block.
func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: input is not a PEM CERTIFICATE block", ErrInvalidCert)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCert, err)
	}
	return cert, nil
}

// hasAnchorExt reports whether a filename is a managed anchor (.crt).
func hasAnchorExt(name string) bool {
	return strings.HasSuffix(name, anchorExt)
}
