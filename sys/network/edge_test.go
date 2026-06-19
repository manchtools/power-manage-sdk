package network

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// --- error branches reached through the Manager ---

func TestApply_PSK_KeyfileWriteFails(t *testing.T) {
	redirectDirs(t)
	swapSeams(t)
	mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: ""}, nil) // not found → create → provisionPSK → writeKeyfile
	_, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi", SSID: "x", AuthType: AuthPSK, PSK: mustSecret(t, "p"),
	})
	if err == nil || !strings.Contains(err.Error(), "create PSK connection") {
		t.Errorf("err = %v, want a wrapped keyfile-write failure", err)
	}
}

func TestApply_PSK_UpdateReloadFails(t *testing.T) {
	redirectDirs(t)
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: "pm-wifi\n"}, nil)                  // exists → update
	r.push(exec.Result{ExitCode: 2, Stderr: "reload failed"}, nil) // reload fails
	_, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi", SSID: "x", AuthType: AuthPSK, PSK: mustSecret(t, "p"),
	})
	if err == nil || !strings.Contains(err.Error(), "update PSK connection") {
		t.Errorf("err = %v, want a wrapped update-reload failure", err)
	}
}

func TestApply_EAPTLS_WriteCertsFails(t *testing.T) {
	_, certBase := redirectDirs(t)
	swapCertSeams(t)
	mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: ""}, nil) // not found → create EAP → writeCerts
	_, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi-eap", SSID: "x", AuthType: AuthEAPTLS, Identity: "u",
		CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: certBase + "/eap",
	})
	if err == nil || !strings.Contains(err.Error(), "write certificates") {
		t.Errorf("err = %v, want a wrapped writeCerts failure", err)
	}
}

func TestNmcliWrite_ExecError(t *testing.T) {
	redirectDirs(t)
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: ""}, nil)                              // not found
	r.push(exec.Result{}, errors.New("sudo: a password is required")) // reload can't execute
	_, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi", SSID: "x", AuthType: AuthPSK, PSK: mustSecret(t, "p"),
	})
	if err == nil || !strings.Contains(err.Error(), "create PSK connection") {
		t.Errorf("err = %v, want the exec-error path wrapped", err)
	}
}

func TestBuildDesiredSettings_HiddenTrue(t *testing.T) {
	d := buildDesiredSettings(Profile{
		SSID: "n", AuthType: AuthEAPTLS, Identity: "u", Hidden: true,
	})
	if d["wifi.hidden"] != "yes" {
		t.Errorf("wifi.hidden = %q, want yes", d["wifi.hidden"])
	}
}

// --- resolvePath defensive branches (path primitives seamed) ---

func swapResolveSeams(t *testing.T) {
	t.Helper()
	oa, oe, os_ := absPath, evalSymlinks, statResolve
	t.Cleanup(func() { absPath, evalSymlinks, statResolve = oa, oe, os_ })
}

func TestResolvePath_AbsFails_RelMismatchRejected(t *testing.T) {
	swapResolveSeams(t)
	// filepath.Abs failing makes resolvePath fall back to Clean(p), which for a
	// relative child stays relative — Rel(absoluteParent, relativeChild) then
	// errors, and isSubdirOf must fail closed.
	absPath = func(p string) (string, error) { return "", errors.New("getwd failed") }
	if isSubdirOf("/var/lib/power-manage/wifi", "relative-child") {
		t.Error("isSubdirOf = true when the paths can't be related (Abs failed)")
	}
}

func TestResolvePath_EvalSymlinksFails_ReturnsAbs(t *testing.T) {
	swapResolveSeams(t)
	evalSymlinks = func(string) (string, error) { return "", errors.New("eval failed") }
	dir := t.TempDir() // exists, already absolute+clean
	if got := resolvePath(dir); got != dir {
		t.Errorf("resolvePath(%q) = %q, want the abs path when EvalSymlinks fails", dir, got)
	}
}

func TestResolvePath_StatAlwaysFails_WalksToRoot(t *testing.T) {
	swapResolveSeams(t)
	// No component "exists" per the seam, so the walk climbs to "/" and breaks on
	// parent==current rather than looping forever.
	statResolve = func(string) (os.FileInfo, error) { return nil, errors.New("stat denied") }
	got := resolvePath("/var/lib/power-manage/wifi/deep/missing")
	if !strings.HasPrefix(got, "/") {
		t.Errorf("resolvePath walked to %q, want an absolute root-anchored path", got)
	}
}
