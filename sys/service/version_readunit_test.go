package service

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// TestVersion_ParsesSystemctlOutput pins the probe's parse contract
// (spec 27): the FIRST integer token of the FIRST line — mirroring the
// install.sh awk this replaces — and an error (never a guessed value)
// for anything else, so the caller's fail-safe (RestrictRealtime=false)
// stays a conscious decision at the call site.
func TestVersion_ParsesSystemctlOutput(t *testing.T) {
	cases := []struct {
		name    string
		stdout  string
		want    int
		wantErr bool
	}{
		{"trixie", "systemd 257 (257.7-1)\n+PAM +AUDIT ...\n", 257, false},
		{"bookworm", "systemd 252 (252.36-1~deb12u1)\n", 252, false},
		{"fedora suffix build", "systemd 256 (256.11-1.fc41)\n", 256, false},
		{"version only", "systemd 258\n", 258, false},
		{"empty output", "", 0, true},
		{"no numeric token", "systemd (unknown)\n", 0, true},
		{"garbage", "command not found", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := exectest.New(exec.Direct)
			f.Push(exec.Result{Stdout: tc.stdout}, nil)
			got, err := mgr(t, f).Version(context.Background())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Version() = %d, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Version(): %v", err)
			}
			if got != tc.want {
				t.Errorf("Version() = %d, want %d", got, tc.want)
			}
			wantOneCmd(t, f, []string{"--version"}, false)
		})
	}
}

func TestVersion_RunnerErrorSurfaces(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{}, errors.New("no systemctl"))
	if _, err := mgr(t, f).Version(context.Background()); err == nil {
		t.Fatal("Version() must surface a runner error")
	}
}

// TestReadUnit_RoundTripsWriteUnitPath pins that ReadUnit reads exactly
// the path WriteUnit writes — the unit path is constructed in one place.
func TestReadUnit_RoundTripsWriteUnitPath(t *testing.T) {
	f := &fakeFS{readContent: "[Unit]\nDescription=demo\n"}
	f.install(t)

	got, err := mgr(t, exectest.New(exec.Sudo)).ReadUnit(context.Background(), "demo.service")
	if err != nil {
		t.Fatal(err)
	}
	if got != "[Unit]\nDescription=demo\n" {
		t.Errorf("ReadUnit content = %q", got)
	}
	if f.readPath != "/etc/systemd/system/demo.service" {
		t.Errorf("ReadUnit path = %q, want /etc/systemd/system/demo.service", f.readPath)
	}
}

func TestReadUnit_AbsentSurfacesErrNotExist(t *testing.T) {
	f := &fakeFS{readErr: fs.ErrNotExist}
	f.install(t)

	_, err := mgr(t, exectest.New(exec.Sudo)).ReadUnit(context.Background(), "demo.service")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadUnit absent err = %v, want fs.ErrNotExist", err)
	}
}

func TestReadUnit_RejectsInvalidUnitName(t *testing.T) {
	f := &fakeFS{}
	f.install(t)

	_, err := mgr(t, exectest.New(exec.Sudo)).ReadUnit(context.Background(), "../../etc/shadow")
	if err == nil || !strings.Contains(err.Error(), "invalid systemd unit name") {
		t.Fatalf("ReadUnit(../../etc/shadow) err = %v, want unit-name rejection", err)
	}
	if f.readPath != "" {
		t.Errorf("ReadUnit must not touch the filesystem for an invalid name, read %q", f.readPath)
	}
}

// TestValidateUnitContent_ExportMatchesGate pins that the exported
// wrapper IS the WriteUnit gate: a dropper unit is rejected, a plain
// unit passes.
func TestValidateUnitContent_ExportMatchesGate(t *testing.T) {
	if err := ValidateUnitContent("[Service]\nExecStart=/bin/sh -c 'curl x | sh'\n"); !errors.Is(err, ErrUnsafeUnitContent) {
		t.Errorf("shell dropper must be rejected, got %v", err)
	}
	if err := ValidateUnitContent("[Service]\nExecStart=/usr/bin/true\n"); err != nil {
		t.Errorf("plain unit must pass, got %v", err)
	}
}

// TestNeedsReload_ParsesShowOutput pins the NeedDaemonReload probe
// (spec 27 reload-retry): yes/no parse strictly, anything else — an
// empty reply, an error line, a D-Bus stall — is an ERROR, never a
// guessed false (fail-closed, matching the package's query posture).
func TestNeedsReload_ParsesShowOutput(t *testing.T) {
	cases := []struct {
		name    string
		stdout  string
		want    bool
		wantErr bool
	}{
		{"pending", "NeedDaemonReload=yes\n", true, false},
		{"clean", "NeedDaemonReload=no\n", false, false},
		{"empty", "", false, true},
		{"garbage", "Failed to get properties", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := exectest.New(exec.Direct)
			f.Push(exec.Result{Stdout: tc.stdout}, nil)
			got, err := mgr(t, f).NeedsReload(context.Background(), "demo.service")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NeedsReload() = %v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NeedsReload(): %v", err)
			}
			if got != tc.want {
				t.Errorf("NeedsReload() = %v, want %v", got, tc.want)
			}
			wantOneCmd(t, f, []string{"show", "--property=NeedDaemonReload", "--", "demo.service"}, false)
		})
	}
}

func TestNeedsReload_RejectsInvalidUnitName(t *testing.T) {
	f := exectest.New(exec.Direct)
	if _, err := mgr(t, f).NeedsReload(context.Background(), "../evil"); err == nil {
		t.Fatal("invalid unit name must be rejected")
	}
	if len(f.Calls()) != 0 {
		t.Fatal("no systemctl call may run for an invalid unit name")
	}
}
