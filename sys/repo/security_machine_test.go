package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

type aptTrustState int

const (
	aptTrustAbsent aptTrustState = iota
	aptTrustSigned
	aptTrustUnsigned
	aptTrustCompromisedConflict
)

type aptTrustTransition struct {
	name         string
	from         aptTrustState
	to           aptTrustState
	repo         Repository
	wantErr      error
	forbidTrust  bool
	forbidExec   bool
	forbidRemove []string
}

// TestAptTrustSecurityMachine keeps package-source trust as a finite state
// machine. An agent that accepts repository actions must not transition from
// absent/signed state into unsigned trust, and cleanup of hostile legacy config
// must not let attacker-controlled Signed-By paths delete arbitrary files.
func TestAptTrustSecurityMachine(t *testing.T) {
	transitions := []aptTrustTransition{
		{
			name:        "absent to unsigned trusted repo is rejected",
			from:        aptTrustAbsent,
			to:          aptTrustUnsigned,
			repo:        Repository{Name: "corp", Apt: &AptConfig{URL: "https://repo.example/deb", Trusted: true}},
			wantErr:     ErrInvalidConfig,
			forbidTrust: true,
			forbidExec:  true,
		},
		{
			name:        "signed repo cannot downgrade to trusted unsigned",
			from:        aptTrustSigned,
			to:          aptTrustUnsigned,
			repo:        Repository{Name: "corp", Apt: &AptConfig{URL: "https://repo.example/deb", Trusted: true}},
			wantErr:     ErrInvalidConfig,
			forbidTrust: true,
			forbidExec:  true,
		},
		{
			name:         "conflict cleanup ignores signed-by outside keyring jail",
			from:         aptTrustCompromisedConflict,
			to:           aptTrustSigned,
			repo:         Repository{Name: "corp", Apt: &AptConfig{URL: "https://repo.example/deb", GPGKey: []byte("armored")}},
			forbidRemove: []string{"Remove:/etc/sudoers", "Remove:/root/.ssh/authorized_keys"},
		},
	}

	for _, tr := range transitions {
		t.Run(tr.name, func(t *testing.T) {
			transition := fmt.Sprintf("%d->%d %s", tr.from, tr.to, tr.name)
			m, ff, fr := newTestManager(t, pkg.Apt)
			seedAptTrustState(ff, tr.from)
			if tr.repo.Apt != nil && len(tr.repo.Apt.GPGKey) > 0 {
				fr.Push(pmexec.Result{Stdout: "BINKEY"}, nil)
			}

			_, err := m.Apply(context.Background(), tr.repo)
			if tr.wantErr != nil && !errors.Is(err, tr.wantErr) {
				t.Fatalf("Apply transition %q = %v, want %v", transition, err, tr.wantErr)
			}
			if tr.wantErr == nil && err != nil {
				t.Fatalf("Apply transition %q unexpected error: %v", transition, err)
			}

			if tr.forbidTrust {
				if body := ff.wrote(aptRepoFile(tr.repo.Name)); strings.Contains(body, "Trusted: yes") {
					t.Fatalf("transition %q wrote an unsigned trust override:\n%s", transition, body)
				}
			}
			if tr.forbidExec && len(fr.Calls()) != 0 {
				t.Fatalf("transition %q ran commands before trust rejection: %+v", transition, fr.Calls())
			}
			for _, forbidden := range tr.forbidRemove {
				if ff.didCall(forbidden) {
					t.Fatalf("transition %q performed forbidden cleanup side effect %s", transition, forbidden)
				}
			}
		})
	}
}

func seedAptTrustState(ff *fakeFS, state aptTrustState) {
	switch state {
	case aptTrustAbsent:
		return
	case aptTrustSigned:
		ff.read[aptRepoFile("corp")] = []byte("# Repository: corp\nTypes: deb\nURIs: https://repo.example/deb\nSuites: /\nSigned-By: /etc/apt/keyrings/corp.gpg\n")
		ff.read[aptKeyFile("corp")] = []byte("BINKEY")
	case aptTrustUnsigned:
		ff.read[aptRepoFile("corp")] = []byte("# Repository: corp\nTypes: deb\nURIs: https://repo.example/deb\nSuites: /\nTrusted: yes\n")
	case aptTrustCompromisedConflict:
		ff.entries[aptSourcesDir] = []fs.DirEntry{{Name: "evil.sources", IsDir: false}}
		ff.read[aptSourcesDir+"/evil.sources"] = []byte(strings.Join([]string{
			"Types: deb",
			"URIs: https://repo.example/deb",
			"Signed-By: /etc/sudoers",
			"Signed-By: /root/.ssh/authorized_keys",
			"",
		}, "\n"))
	}
}
