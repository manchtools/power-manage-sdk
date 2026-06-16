package network

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// networkManager is the nmcli-backed Manager. Reads (con show) run unprivileged;
// mutations (con add/mod/delete, connection reload) escalate through the Runner.
// The WPA PSK is never passed on argv — it is provisioned via a 0600 keyfile
// (provisionPSK) — and the EAP-TLS client key likewise lives only in its 0600
// cert file.
type networkManager struct {
	r exec.Runner
}

// nmcliRead runs an unprivileged nmcli query and returns stdout, mapping a
// non-zero exit (or a failure to execute) to an error.
func (m *networkManager) nmcliRead(ctx context.Context, args ...string) (string, error) {
	res, err := m.r.Run(ctx, exec.Command{Name: "nmcli", Args: args})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", &exec.CommandError{Name: "nmcli", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return res.Stdout, nil
}

// nmcliWrite runs an escalated nmcli mutation, mapping a non-zero exit (or a
// failure to execute) to an error.
func (m *networkManager) nmcliWrite(ctx context.Context, args ...string) error {
	res, err := m.r.Run(ctx, exec.Command{Name: "nmcli", Args: args, Escalate: true})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return &exec.CommandError{Name: "nmcli", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}

// ConnectionExists lists all connection names and searches for an exact match so
// that real failures (NetworkManager not running, nmcli missing, ctx cancelled)
// propagate as errors instead of collapsing into "not found".
func (m *networkManager) ConnectionExists(ctx context.Context, name string) (bool, error) {
	out, err := m.nmcliRead(ctx, "-t", "-f", "NAME", "con", "show")
	if err != nil {
		return false, fmt.Errorf("list connections: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		// Only strip CR (for CRLF endings); leading/trailing whitespace can be
		// part of a connection name.
		if unescapeNmcli(strings.TrimRight(line, "\r")) == name {
			return true, nil
		}
	}
	return false, nil
}

// Settings retrieves a connection's current settings as a key-value map. Values
// are unescaped from nmcli terse-mode encoding (\: -> :, \\ -> \).
func (m *networkManager) Settings(ctx context.Context, name string) (map[string]string, error) {
	out, err := m.nmcliRead(ctx, "-t", "-f", "all", "con", "show", name)
	if err != nil {
		return nil, fmt.Errorf("get settings for %s: %w", name, err)
	}
	settings := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			// Keys are nmcli field names (no whitespace); values may contain
			// meaningful leading/trailing whitespace (SSIDs) and must not be
			// trimmed.
			settings[parts[0]] = unescapeNmcli(parts[1])
		}
	}
	return settings, nil
}

// Apply creates or updates a WiFi connection profile, returning whether a change
// was made.
func (m *networkManager) Apply(ctx context.Context, p Profile) (bool, error) {
	if err := validateProfile(p); err != nil {
		return false, err
	}
	exists, err := m.ConnectionExists(ctx, p.Name)
	if err != nil {
		return false, err
	}
	if exists {
		return m.update(ctx, p)
	}
	return m.create(ctx, p)
}

// create provisions a new connection. PSK profiles take the keyfile path; EAP-TLS
// profiles write their certs then `nmcli con add` (cleaning up certs on failure
// since no connection exists to use them).
func (m *networkManager) create(ctx context.Context, p Profile) (bool, error) {
	if p.AuthType == AuthPSK {
		if err := m.provisionPSK(ctx, p); err != nil {
			return false, fmt.Errorf("create PSK connection: %w", err)
		}
		return true, nil
	}
	// EAP-TLS (validateProfile guarantees no other auth type reaches here).
	if err := writeCerts(p); err != nil {
		return false, fmt.Errorf("write certificates: %w", err)
	}
	if err := m.nmcliWrite(ctx, buildAddArgs(p)...); err != nil {
		removeCerts(p.CertDir)
		return false, fmt.Errorf("create connection: %w", err)
	}
	return true, nil
}

// update reconciles an existing connection. PSK profiles always rewrite the
// keyfile (nmcli cannot read the PSK back to diff it, so any other drift check
// would assume the PSK is unchanged — the surprising failure mode where a
// rotation seems to vanish). EAP-TLS profiles diff against the live settings and,
// when changed, stage the cert swap so a partial read never destroys the live
// cert directory.
func (m *networkManager) update(ctx context.Context, p Profile) (bool, error) {
	if p.AuthType == AuthPSK {
		if err := m.provisionPSK(ctx, p); err != nil {
			return false, fmt.Errorf("update PSK connection: %w", err)
		}
		return true, nil
	}
	// EAP-TLS (validateProfile guarantees no other auth type reaches here).
	current, err := m.Settings(ctx, p.Name)
	if err != nil {
		// Can't read current settings — modify anyway, but staged so a partial
		// read never overwrites the live cert dir.
		return m.stagedModify(ctx, p, nil)
	}
	if !needsModify(current, p) {
		return false, nil
	}
	return m.stagedModify(ctx, p, current)
}

// provisionPSK writes the 0600 keyfile for a PSK profile and reloads
// NetworkManager. The PSK reaches disk only through the keyfile; it never
// touches argv.
func (m *networkManager) provisionPSK(ctx context.Context, p Profile) error {
	if err := writeKeyfile(keyfilePath(p.Name), buildPSKKeyfile(p)); err != nil {
		return err
	}
	if err := m.nmcliWrite(ctx, "connection", "reload"); err != nil {
		return fmt.Errorf("nmcli connection reload: %w", err)
	}
	return nil
}

// stagedModify applies an EAP-TLS modify with cert staging. New certs are written
// to <CertDir>.tmp, nmcli is reconfigured to point at the FINAL cert paths, and
// only after nmcli succeeds is the directory swapped via rename-over with
// rollback. The live cert directory is never destroyed before the staged copy is
// in place.
func (m *networkManager) stagedModify(ctx context.Context, p Profile, current map[string]string) (bool, error) {
	tmpDir := p.CertDir + ".tmp"
	staged := p
	staged.CertDir = tmpDir
	defer removeAll(tmpDir) // best-effort cleanup if anything below fails

	if err := writeCerts(staged); err != nil {
		return false, fmt.Errorf("write staged certificates: %w", err)
	}

	// Modify with the FINAL cert paths (not temp), so nmcli's config never
	// references the temp dir, then move temp into place.
	if err := m.nmcliWrite(ctx, buildModifyArgs(p, current)...); err != nil {
		return false, fmt.Errorf("modify connection: %w", err)
	}

	// nmcli succeeded — swap staged certs into place: live → .old, staged →
	// live, then delete .old. On failure, restore .old so we never leave a
	// missing cert directory.
	oldDir := p.CertDir + ".old"
	liveExists := false
	if _, err := statFile(p.CertDir); err == nil {
		if err := renameFile(p.CertDir, oldDir); err != nil {
			return true, fmt.Errorf("backup old cert directory: %w", err)
		}
		liveExists = true
	}
	if err := renameFile(tmpDir, p.CertDir); err != nil {
		if liveExists {
			if rerr := renameFile(oldDir, p.CertDir); rerr != nil {
				return true, fmt.Errorf("install staged certs: %w (rollback also failed: %v)", err, rerr)
			}
		}
		return true, fmt.Errorf("install staged certs: %w", err)
	}
	if liveExists {
		removeAll(oldDir)
	}
	return true, nil
}

// Delete removes a WiFi connection by name and, if opts.CertDir is set, cleans up
// its cert directory.
func (m *networkManager) Delete(ctx context.Context, name string, opts DeleteOptions) error {
	exists, err := m.ConnectionExists(ctx, name)
	if err != nil {
		return err
	}
	if exists {
		if err := m.nmcliWrite(ctx, "con", "delete", name); err != nil {
			return fmt.Errorf("delete connection %s: %w", name, err)
		}
	}
	if opts.CertDir != "" {
		if err := safeRemoveCertDir(opts.CertDir); err != nil {
			return err
		}
	}
	return nil
}

// needsModify performs a two-way comparison between current settings and the
// desired EAP-TLS settings. It also compares the desired PEM contents against the
// files on disk so a cert rotation (same paths, new content) triggers a re-write.
func needsModify(current map[string]string, p Profile) bool {
	desired := buildDesiredSettings(p)
	for key, want := range desired {
		if current[key] != want {
			return true
		}
	}
	for _, key := range allManagedKeys() {
		if _, inCurrent := current[key]; !inCurrent {
			continue
		}
		if _, inDesired := desired[key]; !inDesired {
			return true
		}
	}
	return certsChanged(p)
}

// buildAddArgs builds nmcli arguments for creating an EAP-TLS WiFi connection.
func buildAddArgs(p Profile) []string {
	args := []string{
		"con", "add",
		"con-name", p.Name,
		"type", "wifi",
		"ssid", p.SSID,
	}
	args = appendEAPAuthArgs(args, p)
	return appendCommonArgs(args, p)
}

// buildModifyArgs builds nmcli arguments for modifying an existing EAP-TLS WiFi
// connection. If current is non-nil, managed keys present in current but absent
// from the desired settings are set to "" to clear them — this is what clears a
// previous mode's fields (e.g. wifi-sec.psk when a PSK connection is converted to
// EAP-TLS).
func buildModifyArgs(p Profile, current map[string]string) []string {
	args := []string{
		"con", "mod", p.Name,
		"wifi.ssid", p.SSID,
	}
	args = appendEAPAuthArgs(args, p)
	args = appendCommonArgs(args, p)

	if current != nil {
		desired := buildDesiredSettings(p)
		for _, key := range allManagedKeys() {
			if _, inCurrent := current[key]; !inCurrent {
				continue
			}
			if _, inDesired := desired[key]; !inDesired {
				args = append(args, key, "")
			}
		}
	}
	return args
}

// appendEAPAuthArgs appends the 802.1X EAP-TLS auth args. Cert paths (not
// contents) go on argv; the private-key contents live in the 0600 cert file.
func appendEAPAuthArgs(args []string, p Profile) []string {
	args = append(args,
		"wifi-sec.key-mgmt", "wpa-eap",
		"802-1x.eap", "tls",
		"802-1x.identity", p.Identity,
	)
	if p.CACert != "" {
		args = append(args, "802-1x.ca-cert", filepath.Join(p.CertDir, "ca.pem"))
	}
	if p.ClientCert != "" {
		args = append(args, "802-1x.client-cert", filepath.Join(p.CertDir, "client.pem"))
	}
	if !p.ClientKey.IsZero() {
		args = append(args, "802-1x.private-key", filepath.Join(p.CertDir, "client-key.pem"))
	}
	return args
}

func appendCommonArgs(args []string, p Profile) []string {
	if p.AutoConnect {
		args = append(args, "connection.autoconnect", "yes")
	} else {
		args = append(args, "connection.autoconnect", "no")
	}
	args = append(args, "connection.autoconnect-priority", fmt.Sprintf("%d", p.Priority))
	if p.Hidden {
		args = append(args, "wifi.hidden", "yes")
	} else {
		args = append(args, "wifi.hidden", "no")
	}
	return args
}

// allManagedKeys returns the union of nmcli keys this package manages across both
// auth modes. The PSK keys are included so a PSK → EAP-TLS conversion clears the
// stale wifi-sec.psk / wifi-sec.key-mgmt that the keyfile path had set.
func allManagedKeys() []string {
	return []string{
		"wifi.ssid",
		"connection.autoconnect",
		"connection.autoconnect-priority",
		"wifi.hidden",
		"wifi-sec.key-mgmt",
		"wifi-sec.psk",
		"802-1x.eap",
		"802-1x.identity",
		"802-1x.ca-cert",
		"802-1x.client-cert",
		"802-1x.private-key",
	}
}

// buildDesiredSettings builds the desired nmcli settings map for an EAP-TLS
// profile (the only auth type that goes through the nmcli diff/modify path; PSK
// is provisioned entirely via keyfile, and its Secret is deliberately kept out of
// any comparison map). Cert keys are the file PATHS, matched against Settings.
func buildDesiredSettings(p Profile) map[string]string {
	desired := map[string]string{
		"wifi.ssid":         p.SSID,
		"wifi-sec.key-mgmt": "wpa-eap",
		"802-1x.eap":        "tls",
		"802-1x.identity":   p.Identity,
	}
	if p.CACert != "" {
		desired["802-1x.ca-cert"] = filepath.Join(p.CertDir, "ca.pem")
	}
	if p.ClientCert != "" {
		desired["802-1x.client-cert"] = filepath.Join(p.CertDir, "client.pem")
	}
	if !p.ClientKey.IsZero() {
		desired["802-1x.private-key"] = filepath.Join(p.CertDir, "client-key.pem")
	}
	if p.AutoConnect {
		desired["connection.autoconnect"] = "yes"
	} else {
		desired["connection.autoconnect"] = "no"
	}
	desired["connection.autoconnect-priority"] = fmt.Sprintf("%d", p.Priority)
	if p.Hidden {
		desired["wifi.hidden"] = "yes"
	} else {
		desired["wifi.hidden"] = "no"
	}
	return desired
}

// unescapeNmcli reverses nmcli terse-mode escaping: \\ -> \, \: -> :
func unescapeNmcli(s string) string {
	s = strings.ReplaceAll(s, `\\`, "\x00")
	s = strings.ReplaceAll(s, `\:`, ":")
	s = strings.ReplaceAll(s, "\x00", `\`)
	return s
}
