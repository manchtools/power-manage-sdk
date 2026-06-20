package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type httpIngressAction int

const (
	httpIngressPinnedFile httpIngressAction = iota
	httpIngressCrossHostRedirect
	httpIngressNegativeSizeCap
	httpIngressPrivilegedMode
	httpIngressDestructiveUnpinnedMirror
)

type httpIngressStep struct {
	name          string
	action        httpIngressAction
	wantNewErr    error
	wantFetchErr  error
	wantNoNetwork bool
	wantNoDisk    bool
}

// TestHTTPIngressSecurityMachine models the remote-source trust boundary as a
// small deterministic automaton: untrusted URL/config input may transition to a
// local filesystem mutation only through the states that keep origin, integrity,
// size, and mode constraints intact. Every reject transition must stop before
// network IO or disk mutation.
func TestHTTPIngressSecurityMachine(t *testing.T) {
	payload := []byte("agent payload\n")
	sum := sha256.Sum256(payload)
	checksum := hex.EncodeToString(sum[:])

	steps := []httpIngressStep{
		{name: "pinned file may enter disk state", action: httpIngressPinnedFile},
		{name: "redirect to another authority stays rejected", action: httpIngressCrossHostRedirect, wantFetchErr: ErrInvalidConfig, wantNoDisk: true},
		{name: "negative size cap stays rejected before fetch", action: httpIngressNegativeSizeCap, wantNewErr: ErrInvalidConfig, wantNoNetwork: true, wantNoDisk: true},
		{name: "privileged mode bits stay rejected before fetch", action: httpIngressPrivilegedMode, wantNewErr: ErrInvalidConfig, wantNoNetwork: true, wantNoDisk: true},
		{name: "extract prune mirror needs integrity pin", action: httpIngressDestructiveUnpinnedMirror, wantNewErr: ErrInvalidConfig, wantNoNetwork: true, wantNoDisk: true},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			machine := newHTTPIngressMachine(t, payload)
			cfg := HTTPConfig{URL: machine.origin.URL + "/payload", ChecksumSHA256: checksum}
			switch step.action {
			case httpIngressPinnedFile:
				// Baseline accepted transition.
			case httpIngressCrossHostRedirect:
				cfg.URL = machine.redirector.URL + "/start"
			case httpIngressNegativeSizeCap:
				cfg.MaxBytes = -1
			case httpIngressPrivilegedMode:
				cfg.Mode = "4755"
			case httpIngressDestructiveUnpinnedMirror:
				cfg.ChecksumSHA256 = ""
				cfg.Extract = true
				cfg.Prune = true
			}

			dest := filepath.Join(t.TempDir(), "payload")
			recordDestUnder(t, dest)
			src, err := NewHTTP(cfg)
			if step.wantNewErr != nil {
				if !errors.Is(err, step.wantNewErr) {
					t.Fatalf("NewHTTP(%s) = %v, want %v", step.name, err, step.wantNewErr)
				}
				machine.assertNoSideEffects(t, dest, step)
				return
			}
			if err != nil {
				t.Fatalf("NewHTTP(%s): %v", step.name, err)
			}

			_, err = src.Fetch(context.Background(), dest)
			if step.wantFetchErr != nil {
				if !errors.Is(err, step.wantFetchErr) {
					t.Fatalf("Fetch(%s) = %v, want %v", step.name, err, step.wantFetchErr)
				}
				machine.assertNoSideEffects(t, dest, step)
				return
			}
			if err != nil {
				t.Fatalf("Fetch(%s): %v", step.name, err)
			}
			if got, err := os.ReadFile(dest); err != nil || string(got) != string(payload) {
				t.Fatalf("accepted transition wrote %q err=%v, want payload %q", got, err, payload)
			}
		})
	}
}

type httpIngressMachine struct {
	originGets   atomic.Int32
	redirectGets atomic.Int32
	origin       *httptest.Server
	redirector   *httptest.Server
}

func newHTTPIngressMachine(t *testing.T, payload []byte) *httpIngressMachine {
	t.Helper()
	m := &httpIngressMachine{}
	m.origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.originGets.Add(1)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(m.origin.Close)
	m.redirector = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.redirectGets.Add(1)
		http.Redirect(w, r, m.origin.URL+"/payload", http.StatusFound)
	}))
	t.Cleanup(m.redirector.Close)
	return m
}

func (m *httpIngressMachine) assertNoSideEffects(t *testing.T, dest string, step httpIngressStep) {
	t.Helper()
	if step.wantNoNetwork && m.originGets.Load()+m.redirectGets.Load() != 0 {
		t.Fatalf("%s performed network IO: origin=%d redirector=%d", step.name, m.originGets.Load(), m.redirectGets.Load())
	}
	if step.action == httpIngressCrossHostRedirect && m.originGets.Load() != 0 {
		t.Fatalf("%s reached redirected origin %d time(s)", step.name, m.originGets.Load())
	}
	if step.wantNoDisk {
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Fatalf("%s mutated destination; stat err=%v", step.name, err)
		}
	}
}
