//go:build integration

package network_test

import (
	"context"
	"os"
	osexec "os/exec"
	"strings"
	"testing"
	"time"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/network"
)

// These exercise the REAL NetworkManager keyfile-based WiFi provisioning against
// a live nmcli + NM daemon (the dedicated with-networkmanager CI job, run as
// root): Apply writes a 0600 keyfile carrying the PSK and `nmcli connection
// reload`s it, NM recognises the profile, and Delete removes it. The security
// property under test is that the PSK is provisioned via the root-owned 0600
// keyfile — never on a command line — proven end-to-end against the real daemon.
//
// No WiFi radio is needed: Apply creates a connection PROFILE, it does not
// activate it, so the keyfile + reload + con-show round-trip works headless.

const keyfileDir = "/etc/NetworkManager/system-connections"

// requireNM gates the test on root + a usable NetworkManager. It SKIPS when
// those are absent so the file is safe to run anywhere — EXCEPT when
// PM_NM_REQUIRED=1 (set by the dedicated test-network CI job, which guarantees
// NM), where a missing prerequisite is a setup failure and must FAIL rather than
// let the job pass vacuously (matches-zero guard: the one test in this job must
// actually run).
func requireNM(t *testing.T) {
	t.Helper()
	bail := t.Skipf
	if os.Getenv("PM_NM_REQUIRED") == "1" {
		bail = t.Fatalf
	}
	if os.Geteuid() != 0 {
		bail("not root; keyfile write + nmcli reload need root")
		return
	}
	if _, err := osexec.LookPath("nmcli"); err != nil {
		bail("nmcli not present; NetworkManager backend not exercisable")
		return
	}
	if len(network.Detect(context.Background())) == 0 {
		bail("nmcli present but NetworkManager not usable here")
		return
	}
}

func TestApplyPSK_Integration(t *testing.T) {
	requireNM(t)
	r, err := pmexec.NewRunner(pmexec.Direct) // root → Direct
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	m, err := network.New(network.NetworkManager, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const name = "pm-test-wifi"
	const ssid = "PMTestNet"
	const pskValue = "pm-test-passphrase-123"
	keyfile := keyfileDir + "/" + name + ".nmconnection"
	t.Cleanup(func() { _ = m.Delete(context.Background(), name, network.DeleteOptions{}) })

	psk, err := pmexec.NewSecret(pskValue)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}

	changed, err := m.Apply(ctx, network.Profile{Name: name, SSID: ssid, AuthType: network.AuthPSK, PSK: psk})
	if err != nil {
		t.Fatalf("Apply(PSK) against real NetworkManager: %v", err)
	}
	if !changed {
		t.Error("first Apply should report changed=true")
	}

	// The PSK must land in a root-owned 0600 keyfile (the secure sink) — not on
	// any argv. Verify both the perms and that the secret is actually there.
	fi, err := os.Stat(keyfile)
	if err != nil {
		t.Fatalf("stat keyfile: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("keyfile mode = %o, want 0600 (the PSK file must not be world/group readable)", perm)
	}
	body := string(mustRead(t, keyfile))
	if !strings.Contains(body, "psk="+pskValue) {
		t.Error("keyfile does not carry the PSK in [wifi-security] (the secure provisioning sink)")
	}
	if !strings.Contains(body, "ssid="+ssid) {
		t.Errorf("keyfile missing ssid=%s", ssid)
	}

	// The live daemon must recognise the reloaded profile.
	exists, err := m.ConnectionExists(ctx, name)
	if err != nil {
		t.Fatalf("ConnectionExists: %v", err)
	}
	if !exists {
		t.Error("NetworkManager did not pick up the connection after `nmcli connection reload`")
	}
	settings, err := m.Settings(ctx, name)
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	if len(settings) == 0 {
		t.Error("Settings returned no keys for the real connection")
	}

	// Delete removes the profile and its keyfile; a second delete is a no-op.
	if err := m.Delete(ctx, name, network.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if exists, err := m.ConnectionExists(ctx, name); err != nil {
		t.Errorf("ConnectionExists after Delete: %v", err)
	} else if exists {
		t.Error("connection still present after Delete")
	}
	if _, err := os.Stat(keyfile); !os.IsNotExist(err) {
		t.Errorf("keyfile still present after Delete: %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
