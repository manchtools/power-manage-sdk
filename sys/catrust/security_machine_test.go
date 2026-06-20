package catrust

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

type trustAnchorAction int

const (
	trustAnchorValidRoot trustAnchorAction = iota
	trustAnchorLeafCert
	trustAnchorCAWithoutCertSign
	trustAnchorFutureCA
	trustAnchorPathName
)

type trustAnchorStep struct {
	name    string
	action  trustAnchorAction
	wantErr error
}

// TestTrustAnchorSecurityMachine models system trust-store mutation as a CA
// capability state machine. Only a currently valid CA certificate with signing
// key usage may transition into the host trust store; every rejected state must
// stop before anchor write or trust-store refresh.
func TestTrustAnchorSecurityMachine(t *testing.T) {
	steps := []trustAnchorStep{
		{name: "valid root CA is accepted", action: trustAnchorValidRoot},
		{name: "leaf certificate is rejected", action: trustAnchorLeafCert, wantErr: ErrInvalidCert},
		{name: "CA without keyCertSign is rejected", action: trustAnchorCAWithoutCertSign, wantErr: ErrInvalidCert},
		{name: "future CA is rejected", action: trustAnchorFutureCA, wantErr: ErrInvalidCert},
		{name: "path-shaped name is rejected", action: trustAnchorPathName, wantErr: ErrInvalidName},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			ff := &fakeFS{}
			m, r := newMgr(t, CaCertificates, ff)
			r.Push(exec.Result{}, nil)
			name, cert := trustAnchorInput(t, step.action)
			err := m.Install(context.Background(), name, cert)
			if step.wantErr != nil {
				if !errors.Is(err, step.wantErr) {
					t.Fatalf("Install(%s) = %v, want %v", step.name, err, step.wantErr)
				}
				if len(ff.writes) != 0 || len(r.Calls()) != 0 {
					t.Fatalf("%s reached trust-store side effects: writes=%+v calls=%+v", step.name, ff.writes, r.Calls())
				}
				return
			}
			if err != nil {
				t.Fatalf("%s unexpected error: %v", step.name, err)
			}
			if len(ff.writes) != 1 || len(r.Calls()) != 1 {
				t.Fatalf("accepted anchor side effects = writes=%d calls=%d, want one write and one refresh", len(ff.writes), len(r.Calls()))
			}
		})
	}
}

func trustAnchorInput(t *testing.T, action trustAnchorAction) (string, []byte) {
	t.Helper()
	now := time.Now()
	switch action {
	case trustAnchorValidRoot:
		return "corp-root", genCert(t, "corp-root", true, now.Add(-time.Hour), now.Add(time.Hour))
	case trustAnchorLeafCert:
		return "leaf", genCert(t, "leaf", false, now.Add(-time.Hour), now.Add(time.Hour))
	case trustAnchorCAWithoutCertSign:
		return "ca-no-sign", genCertWithKeyUsage(t, "ca-no-sign", true, now.Add(-time.Hour), now.Add(time.Hour), x509.KeyUsageDigitalSignature)
	case trustAnchorFutureCA:
		return "future-root", genCert(t, "future-root", true, now.Add(time.Hour), now.Add(2*time.Hour))
	case trustAnchorPathName:
		return "../corp-root", genCert(t, "corp-root", true, now.Add(-time.Hour), now.Add(time.Hour))
	default:
		return "corp-root", genCert(t, "corp-root", true, now.Add(-time.Hour), now.Add(time.Hour))
	}
}
