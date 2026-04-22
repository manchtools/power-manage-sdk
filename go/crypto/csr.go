// Package crypto provides cryptographic utilities for certificate management.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// GenerateCSR creates a new ECDSA P-256 key pair and returns the CSR (PEM)
// and private key (PEM).
//
// The CSR carries no SANs (no DNSNames, IPAddresses, EmailAddresses,
// or URIs). Agent certificates are client certs — identified by the
// deviceID that the Control Server writes into the issued cert's
// Subject.SerialNumber, not by anything the agent puts in the CSR.
// The Control Server's CA rejects any CSR with SANs:
//
//     internal/ca/ca.go: "CSR must not request subject alternative names"
//
// so including a DNS SAN here fails registration immediately. The
// hostname is still put in the CSR's CN for operator debuggability
// (the CA discards the CN and replaces it with the device ID), but
// the DNS SAN is omitted.
func GenerateCSR(hostname string) (csrPEM, keyPEM []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostname,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return csrPEM, keyPEM, nil
}

// GenerateCSRFromKey creates a CSR using an existing PEM-encoded ECDSA private key.
// This is used for certificate renewal where the key pair is reused.
func GenerateCSRFromKey(hostname string, keyPEM []byte) (csrPEM []byte, err error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// No SANs — see GenerateCSR for the rationale. Renewal CSRs
	// follow the same shape as initial-enrolment CSRs.
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostname,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}
