package network

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// recordingRunner is an exec.Runner that records every Command (so a test can
// assert the exact nmcli argv and prove no Secret ever reaches it) and scripts
// the Run results FIFO. Network credentials never travel through the Runner at
// all — the PSK lands in a keyfile and the EAP-TLS client key in a cert file —
// so the proof here is "secret appears in NO recorded argv/stdin".
type recordingRunner struct {
	mu      sync.Mutex
	calls   []capturedCall
	results []scripted
}

type capturedCall struct {
	cmd   exec.Command
	stdin string
}

type scripted struct {
	res exec.Result
	err error
}

func (r *recordingRunner) push(res exec.Result, err error) {
	r.results = append(r.results, scripted{res, err})
}

func (r *recordingRunner) record(c exec.Command) (exec.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cc := capturedCall{cmd: c}
	if c.Stdin != nil {
		b, _ := io.ReadAll(c.Stdin)
		cc.stdin = string(b)
	}
	r.calls = append(r.calls, cc)
	if len(r.results) == 0 {
		return exec.Result{}, nil
	}
	s := r.results[0]
	r.results = r.results[1:]
	return s.res, s.err
}

func (r *recordingRunner) Run(ctx context.Context, c exec.Command) (exec.Result, error) {
	return r.record(c)
}
func (r *recordingRunner) Stream(ctx context.Context, c exec.Command, _ exec.OutputCallback) (exec.Result, error) {
	return r.record(c)
}
func (r *recordingRunner) Backend() exec.PrivilegeBackend { return exec.Direct }

var _ exec.Runner = (*recordingRunner)(nil)

func mgr(t *testing.T, r exec.Runner) Manager {
	t.Helper()
	m, err := New(NetworkManager, r)
	if err != nil {
		t.Fatalf("New(NetworkManager): %v", err)
	}
	return m
}

func mustSecret(t *testing.T, s string) exec.Secret {
	t.Helper()
	sec, err := exec.NewSecret(s)
	if err != nil {
		t.Fatalf("NewSecret(%q): %v", s, err)
	}
	return sec
}

// realPEMKey is a realistic multi-line PEM private key body. The newlines are the
// whole point: it can only be a Secret via NewMultilineSecret, and it must reach
// disk (the 0600 cert file) but never argv.
const realPEMKey = "-----BEGIN PRIVATE KEY-----\n" +
	"MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA1example\n" +
	"key-material-line-two-distinctive-marker\n" +
	"-----END PRIVATE KEY-----\n"

const (
	realCACert     = "-----BEGIN CERTIFICATE-----\nCA-distinctive\n-----END CERTIFICATE-----\n"
	realClientCert = "-----BEGIN CERTIFICATE-----\nCLIENT-distinctive\n-----END CERTIFICATE-----\n"
)

// redirectDirs points the keyfile + cert-base seams at writable temp dirs and
// returns them. Restores on cleanup.
func redirectDirs(t *testing.T) (keyDir, certBase string) {
	t.Helper()
	keyDir = t.TempDir()
	certBase = t.TempDir()
	origKey, origBase := nmKeyfileDir, certBaseDir
	nmKeyfileDir = keyDir
	certBaseDir = certBase
	t.Cleanup(func() { nmKeyfileDir, certBaseDir = origKey, origBase })
	return keyDir, certBase
}

// assertNoSecretInCalls fails if any secret plaintext appears in any recorded
// nmcli argv or stdin.
func assertNoSecretInCalls(t *testing.T, calls []capturedCall, secrets ...string) {
	t.Helper()
	for _, cc := range calls {
		for _, a := range cc.cmd.Args {
			for _, s := range secrets {
				if s != "" && strings.Contains(a, s) {
					t.Errorf("secret plaintext %q leaked into nmcli argv: %q (full: %v)", s, a, cc.cmd.Args)
				}
			}
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(cc.stdin, s) {
				t.Errorf("secret plaintext %q leaked into nmcli stdin", s)
			}
		}
	}
}

func TestNew_FailClosed(t *testing.T) {
	r := &recordingRunner{}
	for _, b := range []Backend{0, Backend(-1), Backend(99)} {
		if _, err := New(b, r); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) err = %v, want ErrUnknownBackend", b, err)
		}
	}
	if _, err := New(NetworkManager, nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
	}
	if _, err := New(NetworkManager, r); err != nil {
		t.Errorf("New(NetworkManager, runner) err = %v, want nil", err)
	}
}

func TestConnectionExists(t *testing.T) {
	t.Run("found (exact match among many)", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: "HomeWifi\npm-wifi-01\nGuestNet\n"}, nil)
		ok, err := mgr(t, r).ConnectionExists(context.Background(), "pm-wifi-01")
		if err != nil || !ok {
			t.Fatalf("ConnectionExists = (%v,%v), want (true,nil)", ok, err)
		}
		c := r.calls[0].cmd
		if c.Name != "nmcli" || c.Escalate {
			t.Errorf("read command = %+v, want unprivileged nmcli", c)
		}
		if strings.Join(c.Args, " ") != "-t -f NAME con show" {
			t.Errorf("argv = %q", strings.Join(c.Args, " "))
		}
	})
	t.Run("not found", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: "HomeWifi\nGuestNet\n"}, nil)
		if ok, _ := mgr(t, r).ConnectionExists(context.Background(), "pm-wifi-01"); ok {
			t.Error("ConnectionExists = true for an absent name")
		}
	})
	t.Run("terse-escaped name match", func(t *testing.T) {
		r := &recordingRunner{}
		// nmcli emits a literal colon in a name as \:
		r.push(exec.Result{Stdout: `Cafe\: Wifi` + "\n"}, nil)
		if ok, err := mgr(t, r).ConnectionExists(context.Background(), "Cafe: Wifi"); err != nil || !ok {
			t.Errorf("ConnectionExists(escaped) = (%v,%v), want (true,nil)", ok, err)
		}
	})
	t.Run("exec failure propagates", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{}, errors.New("nmcli: command not found"))
		if _, err := mgr(t, r).ConnectionExists(context.Background(), "x"); err == nil {
			t.Error("ConnectionExists swallowed an exec failure")
		}
	})
	t.Run("non-zero exit propagates", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 8, Stderr: "Error: NetworkManager is not running"}, nil)
		if _, err := mgr(t, r).ConnectionExists(context.Background(), "x"); err == nil {
			t.Error("ConnectionExists swallowed a non-zero exit")
		}
	})
}

func TestSettings(t *testing.T) {
	t.Run("parses and unescapes", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: "connection.id:pm-wifi-01\r\n" +
			"wifi.ssid:CorpNet\n" +
			`ipv4.routes:10.0.0.0/8\: via\\gw` + "\n" +
			"malformed-no-colon\n"}, nil)
		got, err := mgr(t, r).Settings(context.Background(), "pm-wifi-01")
		if err != nil {
			t.Fatal(err)
		}
		if got["connection.id"] != "pm-wifi-01" || got["wifi.ssid"] != "CorpNet" {
			t.Errorf("settings = %v", got)
		}
		if got["ipv4.routes"] != `10.0.0.0/8: via\gw` {
			t.Errorf("unescape wrong: %q", got["ipv4.routes"])
		}
		if _, ok := got["malformed-no-colon"]; ok {
			t.Error("a line without a colon should be skipped, not stored")
		}
		c := r.calls[0].cmd
		if c.Escalate || strings.Join(c.Args, " ") != "-t -f all con show pm-wifi-01" {
			t.Errorf("read command = %+v", c)
		}
	})
	t.Run("exec/exit failure propagates", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 10, Stderr: "unknown connection"}, nil)
		if _, err := mgr(t, r).Settings(context.Background(), "ghost"); err == nil {
			t.Error("Settings swallowed a non-zero exit")
		}
	})
}

func TestApply_PSK_Create(t *testing.T) {
	keyDir, _ := redirectDirs(t)
	const psk = "Hunter2-Corp-PSK-distinctive"
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: "OtherNet\n"}, nil) // ConnectionExists → not found

	changed, err := mgr(t, r).Apply(context.Background(), Profile{
		Name:        "pm-wifi-01",
		SSID:        "CorpNet",
		AuthType:    AuthPSK,
		PSK:         mustSecret(t, psk),
		AutoConnect: true,
		Priority:    10,
	})
	if err != nil || !changed {
		t.Fatalf("Apply = (%v,%v), want (true,nil)", changed, err)
	}

	// Keyfile written, 0600, carries the PSK.
	body, err := os.ReadFile(filepath.Join(keyDir, "pm-wifi-01.nmconnection"))
	if err != nil {
		t.Fatalf("keyfile not written: %v", err)
	}
	if !strings.Contains(string(body), "psk="+psk) {
		t.Errorf("keyfile missing psk: %s", body)
	}
	info, _ := os.Stat(filepath.Join(keyDir, "pm-wifi-01.nmconnection"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("keyfile mode = %o, want 0600", info.Mode().Perm())
	}

	// Commands: [0] con show (read), [1] connection reload (escalated). The PSK
	// is in NEITHER.
	if len(r.calls) != 2 {
		t.Fatalf("ran %d commands, want 2 (con show, connection reload)", len(r.calls))
	}
	reload := r.calls[1].cmd
	if !reload.Escalate || strings.Join(reload.Args, " ") != "connection reload" {
		t.Errorf("second command = %+v, want escalated `connection reload`", reload)
	}
	assertNoSecretInCalls(t, r.calls, psk)
}

func TestApply_PSK_Update(t *testing.T) {
	keyDir, _ := redirectDirs(t)
	const psk = "Rotated-PSK-distinctive"
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: "pm-wifi-01\n"}, nil) // exists

	changed, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi-01", SSID: "CorpNet", AuthType: AuthPSK, PSK: mustSecret(t, psk),
	})
	if err != nil || !changed {
		t.Fatalf("Apply(update) = (%v,%v), want (true,nil)", changed, err)
	}
	body, _ := os.ReadFile(filepath.Join(keyDir, "pm-wifi-01.nmconnection"))
	if !strings.Contains(string(body), "psk="+psk) {
		t.Errorf("rotated keyfile missing new psk: %s", body)
	}
	assertNoSecretInCalls(t, r.calls, psk)
}

func TestApply_PSK_ReloadFailure(t *testing.T) {
	redirectDirs(t)
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: ""}, nil)                                  // not found
	r.push(exec.Result{ExitCode: 2, Stderr: "Error: reload failed"}, nil) // reload fails
	_, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi-01", SSID: "CorpNet", AuthType: AuthPSK, PSK: mustSecret(t, "p"),
	})
	if err == nil || !strings.Contains(err.Error(), "create PSK connection") {
		t.Errorf("Apply err = %v, want a wrapped reload failure", err)
	}
}

func TestApply_EAPTLS_Create(t *testing.T) {
	_, certBase := redirectDirs(t)
	certDir := filepath.Join(certBase, "pm-wifi-eap")
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: "OtherNet\n"}, nil) // not found

	changed, err := mgr(t, r).Apply(context.Background(), Profile{
		Name:       "pm-wifi-eap",
		SSID:       "SecureNet",
		AuthType:   AuthEAPTLS,
		Identity:   "device@corp.example.com",
		CACert:     realCACert,
		ClientCert: realClientCert,
		ClientKey:  exec.NewMultilineSecret(realPEMKey),
		CertDir:    certDir,
	})
	if err != nil || !changed {
		t.Fatalf("Apply = (%v,%v), want (true,nil)", changed, err)
	}

	// Client key on disk, 0600; cert paths (not contents) in argv.
	key, err := os.ReadFile(filepath.Join(certDir, "client-key.pem"))
	if err != nil || string(key) != realPEMKey {
		t.Fatalf("client-key.pem = %q (err %v), want the verbatim PEM", key, err)
	}
	if info, _ := os.Stat(filepath.Join(certDir, "client-key.pem")); info.Mode().Perm() != 0o600 {
		t.Errorf("client-key.pem mode = %o, want 0600", info.Mode().Perm())
	}
	add := r.calls[1].cmd
	if !add.Escalate || add.Args[0] != "con" || add.Args[1] != "add" {
		t.Errorf("create command = %+v, want escalated `con add`", add)
	}
	if !strings.Contains(strings.Join(add.Args, " "), filepath.Join(certDir, "client-key.pem")) {
		t.Error("argv should reference the client-key PATH")
	}
	assertNoSecretInCalls(t, r.calls, realPEMKey, "key-material-line-two-distinctive-marker")
}

func TestApply_EAPTLS_CreateFailureCleansCerts(t *testing.T) {
	_, certBase := redirectDirs(t)
	certDir := filepath.Join(certBase, "pm-wifi-eap")
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: ""}, nil)                               // not found
	r.push(exec.Result{ExitCode: 1, Stderr: "Error: add failed"}, nil) // con add fails

	_, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi-eap", SSID: "SecureNet", AuthType: AuthEAPTLS,
		Identity: "u", CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: certDir,
	})
	if err == nil {
		t.Fatal("Apply returned nil on con-add failure")
	}
	// Certs cleaned up since the connection never came into being.
	if _, err := os.Stat(filepath.Join(certDir, "client-key.pem")); !os.IsNotExist(err) {
		t.Error("client-key.pem should have been removed after add failure")
	}
}

func TestApply_EAPTLS_UpdateWithDrift(t *testing.T) {
	_, certBase := redirectDirs(t)
	certDir := filepath.Join(certBase, "pm-wifi-eap")
	// Pre-existing live certs (old content).
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ca.pem", "client.pem", "client-key.pem"} {
		os.WriteFile(filepath.Join(certDir, n), []byte("OLD"), 0o600)
	}
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: "pm-wifi-eap\n"}, nil) // exists
	// current settings differ (old ssid) → needsModify.
	r.push(exec.Result{Stdout: "wifi.ssid:OldName\nwifi-sec.key-mgmt:wpa-eap\n"}, nil)

	changed, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi-eap", SSID: "SecureNet", AuthType: AuthEAPTLS,
		Identity: "device@corp.example.com", CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: certDir, AutoConnect: true,
	})
	if err != nil || !changed {
		t.Fatalf("Apply(update drift) = (%v,%v), want (true,nil)", changed, err)
	}
	// New certs swapped into the live dir; the staging dir is gone.
	key, _ := os.ReadFile(filepath.Join(certDir, "client-key.pem"))
	if string(key) != realPEMKey {
		t.Errorf("client-key not rotated: %q", key)
	}
	if _, err := os.Stat(certDir + ".tmp"); !os.IsNotExist(err) {
		t.Error(".tmp staging dir should be gone")
	}
	if _, err := os.Stat(certDir + ".old"); !os.IsNotExist(err) {
		t.Error(".old backup dir should be gone")
	}
	mod := r.calls[2].cmd
	if mod.Args[0] != "con" || mod.Args[1] != "mod" {
		t.Errorf("third command = %v, want `con mod`", mod.Args)
	}
	assertNoSecretInCalls(t, r.calls, realPEMKey)
}

func TestApply_EAPTLS_UpdateNoChange(t *testing.T) {
	_, certBase := redirectDirs(t)
	certDir := filepath.Join(certBase, "pm-wifi-eap")
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// On-disk certs already match the desired content (certsChanged=false).
	os.WriteFile(filepath.Join(certDir, "ca.pem"), []byte(realCACert), 0o640)
	os.WriteFile(filepath.Join(certDir, "client.pem"), []byte(realClientCert), 0o640)
	os.WriteFile(filepath.Join(certDir, "client-key.pem"), []byte(realPEMKey), 0o600)

	r := &recordingRunner{}
	r.push(exec.Result{Stdout: "pm-wifi-eap\n"}, nil) // exists
	// current settings already match desired exactly.
	current := "wifi.ssid:SecureNet\n" +
		"wifi-sec.key-mgmt:wpa-eap\n" +
		"802-1x.eap:tls\n" +
		"802-1x.identity:device@corp.example.com\n" +
		"802-1x.ca-cert:" + filepath.Join(certDir, "ca.pem") + "\n" +
		"802-1x.client-cert:" + filepath.Join(certDir, "client.pem") + "\n" +
		"802-1x.private-key:" + filepath.Join(certDir, "client-key.pem") + "\n" +
		"connection.autoconnect:yes\n" +
		"connection.autoconnect-priority:0\n" +
		"wifi.hidden:no\n"
	r.push(exec.Result{Stdout: current}, nil)

	changed, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi-eap", SSID: "SecureNet", AuthType: AuthEAPTLS,
		Identity: "device@corp.example.com", CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: certDir, AutoConnect: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("Apply reported a change when nothing drifted")
	}
	if len(r.calls) != 2 {
		t.Errorf("ran %d commands, want 2 (con show + settings, no modify)", len(r.calls))
	}
}

func TestApply_EAPTLS_UpdateSettingsErrorStillStages(t *testing.T) {
	_, certBase := redirectDirs(t)
	certDir := filepath.Join(certBase, "pm-wifi-eap")
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: "pm-wifi-eap\n"}, nil)                      // exists
	r.push(exec.Result{ExitCode: 10, Stderr: "settings read failed"}, nil) // Settings fails

	changed, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi-eap", SSID: "SecureNet", AuthType: AuthEAPTLS,
		Identity: "u", CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: certDir,
	})
	if err != nil || !changed {
		t.Fatalf("Apply(settings-error) = (%v,%v), want (true,nil) via staged modify", changed, err)
	}
	if _, err := os.Stat(filepath.Join(certDir, "client-key.pem")); err != nil {
		t.Errorf("certs should be installed even when the settings read failed: %v", err)
	}
}

func TestApply_RejectsInvalidProfileBeforeAnyCommand(t *testing.T) {
	redirectDirs(t)
	r := &recordingRunner{}
	// EAP-TLS with a CertDir OUTSIDE the base must be rejected before nmcli runs.
	_, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi", SSID: "x", AuthType: AuthEAPTLS, Identity: "u",
		CACert: realCACert, ClientCert: realClientCert,
		ClientKey: exec.NewMultilineSecret(realPEMKey), CertDir: "/tmp/evil-escape",
	})
	if err == nil {
		t.Fatal("Apply accepted a CertDir outside CertBaseDir")
	}
	if len(r.calls) != 0 {
		t.Errorf("ran %d commands for an invalid profile; validation must precede execution", len(r.calls))
	}
}

func TestApply_ConnectionExistsErrorAborts(t *testing.T) {
	redirectDirs(t)
	r := &recordingRunner{}
	r.push(exec.Result{}, errors.New("nmcli down"))
	if _, err := mgr(t, r).Apply(context.Background(), Profile{
		Name: "pm-wifi", SSID: "x", AuthType: AuthPSK, PSK: mustSecret(t, "p"),
	}); err == nil {
		t.Error("Apply continued past a ConnectionExists failure")
	}
}

func TestDelete(t *testing.T) {
	t.Run("exists: deletes and cleans certs", func(t *testing.T) {
		_, certBase := redirectDirs(t)
		certDir := filepath.Join(certBase, "pm-wifi-eap")
		os.MkdirAll(certDir, 0o750)
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: "pm-wifi-eap\n"}, nil) // exists
		if err := mgr(t, r).Delete(context.Background(), "pm-wifi-eap", DeleteOptions{CertDir: certDir}); err != nil {
			t.Fatal(err)
		}
		del := r.calls[1].cmd
		if !del.Escalate || strings.Join(del.Args, " ") != "con delete pm-wifi-eap" {
			t.Errorf("delete command = %+v", del)
		}
		if _, err := os.Stat(certDir); !os.IsNotExist(err) {
			t.Error("cert dir should be removed")
		}
	})
	t.Run("absent: skips delete, still cleans certs", func(t *testing.T) {
		_, certBase := redirectDirs(t)
		certDir := filepath.Join(certBase, "pm-wifi-eap")
		os.MkdirAll(certDir, 0o750)
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: "OtherNet\n"}, nil) // not found
		if err := mgr(t, r).Delete(context.Background(), "pm-wifi-eap", DeleteOptions{CertDir: certDir}); err != nil {
			t.Fatal(err)
		}
		if len(r.calls) != 1 {
			t.Errorf("ran %d commands, want 1 (con show only — no delete for an absent connection)", len(r.calls))
		}
		if _, err := os.Stat(certDir); !os.IsNotExist(err) {
			t.Error("cert dir should still be removed for an absent connection")
		}
	})
	t.Run("no certdir: delete only", func(t *testing.T) {
		redirectDirs(t)
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: "pm-wifi\n"}, nil)
		if err := mgr(t, r).Delete(context.Background(), "pm-wifi", DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ConnectionExists error aborts", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{}, errors.New("nmcli down"))
		if err := mgr(t, r).Delete(context.Background(), "pm-wifi", DeleteOptions{}); err == nil {
			t.Error("Delete continued past a ConnectionExists failure")
		}
	})
	t.Run("con delete failure propagates", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: "pm-wifi\n"}, nil)
		r.push(exec.Result{ExitCode: 1, Stderr: "Error: delete failed"}, nil)
		if err := mgr(t, r).Delete(context.Background(), "pm-wifi", DeleteOptions{}); err == nil {
			t.Error("Delete swallowed a con-delete failure")
		}
	})
	t.Run("cert cleanup rejects an out-of-base dir", func(t *testing.T) {
		redirectDirs(t)
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: "OtherNet\n"}, nil) // not found → straight to cert cleanup
		if err := mgr(t, r).Delete(context.Background(), "pm-wifi", DeleteOptions{CertDir: "/tmp/evil"}); err == nil {
			t.Error("Delete accepted a cert dir outside CertBaseDir")
		}
	})
}

func TestValidateProfile(t *testing.T) {
	_, certBase := redirectDirs(t)
	good := filepath.Join(certBase, "ok")
	tests := []struct {
		name    string
		profile Profile
		wantErr bool
	}{
		{"valid PSK", Profile{Name: "t", SSID: "n", AuthType: AuthPSK, PSK: mustSecret(t, "pass")}, false},
		{"valid EAP-TLS", Profile{Name: "t", SSID: "n", AuthType: AuthEAPTLS, Identity: "u", CertDir: good, ClientCert: "c", ClientKey: exec.NewMultilineSecret(realPEMKey)}, false},
		{"missing name", Profile{SSID: "n", AuthType: AuthPSK, PSK: mustSecret(t, "p")}, true},
		{"missing SSID", Profile{Name: "t", AuthType: AuthPSK, PSK: mustSecret(t, "p")}, true},
		{"empty PSK", Profile{Name: "t", SSID: "n", AuthType: AuthPSK}, true},
		{"missing identity", Profile{Name: "t", SSID: "n", AuthType: AuthEAPTLS, CertDir: good, ClientCert: "c", ClientKey: exec.NewMultilineSecret("k")}, true},
		{"missing certdir", Profile{Name: "t", SSID: "n", AuthType: AuthEAPTLS, Identity: "u", ClientCert: "c", ClientKey: exec.NewMultilineSecret("k")}, true},
		{"certdir outside base", Profile{Name: "t", SSID: "n", AuthType: AuthEAPTLS, Identity: "u", CertDir: "/tmp/evil", ClientCert: "c", ClientKey: exec.NewMultilineSecret("k")}, true},
		{"certdir is base itself", Profile{Name: "t", SSID: "n", AuthType: AuthEAPTLS, Identity: "u", CertDir: certBase, ClientCert: "c", ClientKey: exec.NewMultilineSecret("k")}, true},
		{"missing client cert", Profile{Name: "t", SSID: "n", AuthType: AuthEAPTLS, Identity: "u", CertDir: good, ClientKey: exec.NewMultilineSecret("k")}, true},
		{"empty client key", Profile{Name: "t", SSID: "n", AuthType: AuthEAPTLS, Identity: "u", CertDir: good, ClientCert: "c"}, true},
		{"unknown auth", Profile{Name: "t", SSID: "n", AuthType: 99}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateProfile(tt.profile); (err != nil) != tt.wantErr {
				t.Errorf("validateProfile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsSubdirOf(t *testing.T) {
	tests := []struct {
		parent, child string
		want          bool
	}{
		{"/var/lib/power-manage/wifi", "/var/lib/power-manage/wifi/abc", true},
		{"/var/lib/power-manage/wifi", "/var/lib/power-manage/wifi/abc/def", true},
		{"/var/lib/power-manage/wifi", "/var/lib/power-manage/wifi", false},
		{"/var/lib/power-manage/wifi", "/tmp/evil", false},
		{"/var/lib/power-manage/wifi", "/var/lib/power-manage/wifi/../x", false},
		{"/var/lib/power-manage/wifi", "/", false},
	}
	for _, tt := range tests {
		t.Run(tt.child, func(t *testing.T) {
			if got := isSubdirOf(tt.parent, tt.child); got != tt.want {
				t.Errorf("isSubdirOf(%q, %q) = %v, want %v", tt.parent, tt.child, got, tt.want)
			}
		})
	}
}

func TestIsSubdirOf_Symlink(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	sub := filepath.Join(base, "sub")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if !isSubdirOf(base, sub) {
		t.Error("real subdirectory should be accepted")
	}
	if isSubdirOf(base, link) {
		t.Error("symlink escaping base should be rejected")
	}
	if isSubdirOf(base, filepath.Join(link, "deep")) {
		t.Error("path under an escaping symlink should be rejected")
	}
}

func TestSafeRemoveCertDir(t *testing.T) {
	_, certBase := redirectDirs(t)
	dir := filepath.Join(certBase, "to-remove")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := safeRemoveCertDir(dir); err != nil {
		t.Errorf("safeRemoveCertDir(valid) = %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("dir not removed")
	}
	if err := safeRemoveCertDir(certBase); err == nil {
		t.Error("removing the base dir itself should be rejected")
	}
	if err := safeRemoveCertDir("/tmp"); err == nil {
		t.Error("a path outside the base should be rejected")
	}
	if err := safeRemoveCertDir(filepath.Join(certBase, "nonexistent")); err != nil {
		t.Errorf("non-existent path under base should be a no-op, got %v", err)
	}
	// A file (not a directory) under the base is rejected.
	f := filepath.Join(certBase, "afile")
	os.WriteFile(f, []byte("x"), 0o600)
	if err := safeRemoveCertDir(f); err == nil {
		t.Error("a non-directory path should be rejected")
	}
}
