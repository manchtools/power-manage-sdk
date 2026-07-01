package repo

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/fs"
)

const (
	aptSourcesDir   = "/etc/apt/sources.list.d"
	aptKeyringDir   = "/etc/apt/keyrings"
	aptLegacyKeyDir = "/etc/apt/trusted.gpg.d"
)

func aptRepoFile(name string) string       { return aptSourcesDir + "/" + name + ".sources" }
func aptLegacyRepoFile(name string) string { return aptSourcesDir + "/" + name + ".list" }
func aptKeyFile(name string) string        { return aptKeyringDir + "/" + name + ".gpg" }
func aptLegacyKeyFile(name string) string  { return aptLegacyKeyDir + "/" + name + ".gpg" }

// aptListSignedBy extracts the keyring path from a one-line .list source, e.g.
// `deb [signed-by=/etc/apt/keyrings/x.gpg] https://…`.
var aptListSignedBy = regexp.MustCompile(`signed-by=([^\s\]]+)`)

// isAptKeyringPath reports whether p is a file directly inside one of the two
// directories where apt signing keyrings legitimately live. Cleanup only removes
// Signed-By targets that pass this jail, so an attacker-controlled source file
// cannot point Signed-By at an arbitrary path (e.g. /etc/sudoers) and turn repo
// reconfiguration into an arbitrary privileged delete. A path is in-jail only if
// it is a direct child of the directory — no traversal, no nested subdirectory.
func isAptKeyringPath(p string) bool {
	for _, dir := range []string{aptKeyringDir, aptLegacyKeyDir} {
		prefix := dir + "/"
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := p[len(prefix):]
		if rest == "" || strings.Contains(rest, "/") || strings.Contains(rest, "..") {
			return false
		}
		return true
	}
	return false
}

// applyApt writes the modern deb822 source to /etc/apt/sources.list.d/<name>.sources,
// installs the (dearmored) signing key under /etc/apt/keyrings, removes any
// conflicting prior configuration of the same URL, and refreshes the index. It is
// idempotent: an unchanged source + key reports Changed=false and skips the
// index refresh.
func (m *manager) applyApt(ctx context.Context, name string, c *AptConfig) (Outcome, error) {
	repoFile := aptRepoFile(name)
	keyFile := aptKeyFile(name)
	var log strings.Builder
	changed := false

	// Remove any other config that uses the same URL — prevents apt's
	// "conflicting values set for option Signed-By" on the next update. A scan
	// failure is surfaced as a warning (in log), never fatal.
	if m.cleanupConflictingApt(ctx, c.URL, repoFile, keyFile, &log) {
		changed = true
	}

	// Clean up legacy single-line .list and trusted.gpg.d key locations.
	legacyFile := aptLegacyRepoFile(name)
	if exists, eerr := m.fsm.Exists(ctx, legacyFile); eerr != nil {
		return Outcome{}, fmt.Errorf("check legacy repo file: %w", eerr)
	} else if exists {
		fmt.Fprintf(&log, "removing legacy repository file: %s\n", legacyFile)
		if rerr := m.fsm.Remove(ctx, legacyFile); rerr != nil {
			fmt.Fprintf(&log, "warning: failed to remove legacy repo file: %v\n", rerr)
		}
		changed = true
	}
	legacyKeyFile := aptLegacyKeyFile(name)
	if exists, eerr := m.fsm.Exists(ctx, legacyKeyFile); eerr != nil {
		return Outcome{}, fmt.Errorf("check legacy GPG key: %w", eerr)
	} else if exists {
		fmt.Fprintf(&log, "removing legacy GPG key: %s\n", legacyKeyFile)
		if rerr := m.fsm.Remove(ctx, legacyKeyFile); rerr != nil {
			fmt.Fprintf(&log, "warning: failed to remove legacy GPG key: %v\n", rerr)
		}
		changed = true
	}

	// Ensure the keyrings directory exists before writing into it.
	if err := m.fsm.Mkdir(ctx, aptKeyringDir, fs.MkdirOptions{Mode: 0o755, Recursive: true}); err != nil {
		return Outcome{}, fmt.Errorf("create keyrings directory: %w", err)
	}

	// Import the signing key (idempotent; updates only when content differs).
	if len(c.GPGKey) > 0 {
		keyUpdated, kerr := m.updateAptKey(ctx, keyFile, c.GPGKey, &log)
		if kerr != nil {
			return Outcome{
				Result:  fsResultErr(log.String(), kerr),
				Changed: false,
			}, kerr
		}
		if keyUpdated {
			log.WriteString("GPG key updated\n")
			changed = true
		} else {
			log.WriteString("GPG key unchanged\n")
		}
	}

	desired := buildAptSources(name, c, keyFile)

	existingBytes, err := m.fsm.ReadFile(ctx, repoFile)
	if err != nil && !isReadAbsent(err) {
		return Outcome{}, fmt.Errorf("read existing repo file: %w", err)
	}
	existing := string(existingBytes)
	if existing == desired && !changed {
		fmt.Fprintf(&log, "repository already up to date: %s\n", name)
		return out(log.String(), false), nil
	}
	if existing != desired {
		if err := m.fsm.WriteFile(ctx, repoFile, []byte(desired), fs.WriteOptions{Mode: 0o644}); err != nil {
			return Outcome{}, fmt.Errorf("write repo file: %w", err)
		}
		fmt.Fprintf(&log, "configured repository: %s\n", name)
		changed = true
	}

	// Refresh the index only when something actually changed (non-fatal: the
	// config landed even if a typo'd URL fails the refresh).
	if changed {
		m.runNonFatal(ctx, &log, fmt.Sprintf("warning: apt-get update failed after configuring %s", name), "apt-get", "update")
	}

	return out(log.String(), changed), nil
}

// buildAptSources renders the deb822 source body. Signed-By takes precedence over
// the legacy Trusted: yes (only one trust mechanism is emitted).
func buildAptSources(name string, c *AptConfig, keyFile string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Repository: %s\n", name)
	b.WriteString("Types: deb\n")
	fmt.Fprintf(&b, "URIs: %s\n", c.URL)
	if c.Distribution != "" {
		fmt.Fprintf(&b, "Suites: %s\n", c.Distribution)
	} else {
		b.WriteString("Suites: /\n")
	}
	if len(c.Components) > 0 {
		fmt.Fprintf(&b, "Components: %s\n", strings.Join(c.Components, " "))
	}
	if c.Arch != "" {
		fmt.Fprintf(&b, "Architectures: %s\n", c.Arch)
	}
	if len(c.GPGKey) > 0 {
		fmt.Fprintf(&b, "Signed-By: %s\n", keyFile)
	} else if c.Trusted {
		b.WriteString("Trusted: yes\n")
	}
	return b.String()
}

// updateAptKey dearmors the public key (unprivileged; binary on stdout, no file
// touched) and writes it to keyFile only when it differs from what is installed.
// Returns whether the keyring changed.
func (m *manager) updateAptKey(ctx context.Context, keyFile string, key []byte, log *strings.Builder) (bool, error) {
	res, err := m.runStdin(ctx, key, "gpg", "--dearmor")
	if err != nil {
		return false, fmt.Errorf("dearmor GPG key: %w", err)
	}
	newKey := []byte(res.Stdout)

	existing, err := m.fsm.ReadFile(ctx, keyFile)
	if err != nil && !isReadAbsent(err) {
		return false, fmt.Errorf("read existing GPG key: %w", err)
	}
	if existing != nil && bytes.Equal(existing, newKey) {
		log.WriteString("GPG key already installed and matches\n")
		return false, nil
	}
	if existing == nil {
		log.WriteString("GPG key not found, installing\n")
	} else {
		log.WriteString("GPG key differs, updating\n")
	}
	if err := m.fsm.WriteFile(ctx, keyFile, newKey, fs.WriteOptions{Mode: 0o644}); err != nil {
		return false, fmt.Errorf("install GPG key: %w", err)
	}
	return true, nil
}

// cleanupConflictingApt scans /etc/apt/sources.list.d for any .sources/.list
// that references url (other than the target's own files) and removes it together
// with its Signed-By keyring. Returns whether anything was removed. A scan error
// is surfaced as a warning and treated as "nothing to clean" rather than failing
// the whole Apply.
func (m *manager) cleanupConflictingApt(ctx context.Context, url, skipRepoFile, skipKeyFile string, log *strings.Builder) bool {
	entries, err := m.fsm.ReadDir(ctx, aptSourcesDir)
	if isReadAbsent(err) {
		return false // no sources.list.d yet → nothing to clean up
	}
	if err != nil {
		fmt.Fprintf(log, "warning: could not scan %s for conflicts: %v\n", aptSourcesDir, err)
		return false
	}
	cleaned := false
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		filename := e.Name
		if !strings.HasSuffix(filename, ".sources") && !strings.HasSuffix(filename, ".list") {
			continue
		}
		filePath := aptSourcesDir + "/" + filename
		if filePath == skipRepoFile {
			continue
		}
		// Skip the legacy .list form of the target repo.
		if strings.TrimSuffix(filePath, ".list")+".sources" == skipRepoFile {
			continue
		}
		contentBytes, rerr := m.fsm.ReadFile(ctx, filePath)
		if rerr != nil {
			continue
		}
		content := string(contentBytes)
		if !strings.Contains(content, url) {
			continue
		}
		fmt.Fprintf(log, "removing conflicting repository config: %s\n", filePath)
		cleaned = true
		m.removeConflictKeys(ctx, filename, content, skipKeyFile, log)
		if rerr := m.fsm.Remove(ctx, filePath); rerr != nil {
			fmt.Fprintf(log, "warning: failed to remove conflicting repo file: %v\n", rerr)
		}
	}
	return cleaned
}

// removeConflictKeys removes the Signed-By keyrings referenced by a conflicting
// source file (deb822 `Signed-By:` lines or one-line `signed-by=`), skipping the
// target repo's own key and any non-absolute reference.
func (m *manager) removeConflictKeys(ctx context.Context, filename, content, skipKeyFile string, log *strings.Builder) {
	var keyPaths []string
	if strings.HasSuffix(filename, ".sources") {
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "Signed-By:") {
				continue
			}
			keyPaths = append(keyPaths, strings.TrimSpace(strings.TrimPrefix(line, "Signed-By:")))
		}
	} else { // .list
		for _, match := range aptListSignedBy.FindAllStringSubmatch(content, -1) {
			keyPaths = append(keyPaths, match[1])
		}
	}
	for _, keyPath := range keyPaths {
		if keyPath == skipKeyFile || !strings.HasPrefix(keyPath, "/") {
			continue
		}
		// Only remove paths inside the apt keyring jail. A hostile Signed-By in a
		// conflicting source file is attacker-controlled config; honoring an
		// arbitrary absolute path here would turn repo cleanup into an arbitrary
		// privileged file delete (e.g. Signed-By: /etc/sudoers). Refuse anything
		// outside the directories apt keyrings legitimately live in.
		if !isAptKeyringPath(keyPath) {
			fmt.Fprintf(log, "refusing to remove out-of-jail Signed-By key: %s\n", keyPath)
			continue
		}
		fmt.Fprintf(log, "removing associated GPG key: %s\n", keyPath)
		if err := m.fsm.Remove(ctx, keyPath); err != nil {
			fmt.Fprintf(log, "warning: failed to remove conflicting GPG key: %v\n", err)
		}
	}
}

// removeApt deletes the deb822 source, the legacy .list, and the keyring. It is
// idempotent: when none of the three exist it reports Changed=false. The primary
// source removal is fatal; the legacy/key removals are best-effort warnings.
func (m *manager) removeApt(ctx context.Context, name string) (Outcome, error) {
	repoFile := aptRepoFile(name)
	legacyFile := aptLegacyRepoFile(name)
	keyFile := aptKeyFile(name)
	var log strings.Builder

	anyExists := false
	for _, p := range []string{repoFile, legacyFile, keyFile} {
		exists, err := m.fsm.Exists(ctx, p)
		if err != nil {
			return Outcome{}, fmt.Errorf("check %s: %w", p, err)
		}
		if exists {
			anyExists = true
		}
	}
	if !anyExists {
		fmt.Fprintf(&log, "repository %s already absent\n", name)
		return out(log.String(), false), nil
	}

	if err := m.fsm.Remove(ctx, repoFile); err != nil {
		return Outcome{}, fmt.Errorf("remove repo file: %w", err)
	}
	if err := m.fsm.Remove(ctx, legacyFile); err != nil {
		fmt.Fprintf(&log, "warning: failed to remove legacy repo file: %v\n", err)
	}
	if err := m.fsm.Remove(ctx, keyFile); err != nil {
		fmt.Fprintf(&log, "warning: failed to remove GPG key: %v\n", err)
	}
	fmt.Fprintf(&log, "removed repository: %s\n", name)
	return out(log.String(), true), nil
}
