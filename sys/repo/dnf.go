package repo

import (
	"context"
	"fmt"
	"strings"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// dnfRepoFile is the .repo path for a named DNF repository.
func dnfRepoFile(name string) string { return "/etc/yum.repos.d/" + name + ".repo" }

// applyDnf writes /etc/yum.repos.d/<name>.repo (idempotently), imports the GPG
// key, and refreshes that repo's metadata. A key-import or refresh failure is
// non-fatal — the repository file was written, so the failure is surfaced as a
// warning in the output rather than discarding a configured repo.
func (m *manager) applyDnf(ctx context.Context, name string, c *DnfConfig) (Outcome, error) {
	repoFile := dnfRepoFile(name)
	var log strings.Builder

	var content strings.Builder
	fmt.Fprintf(&content, "[%s]\n", name)
	if c.Description != "" {
		fmt.Fprintf(&content, "name=%s\n", c.Description)
	} else {
		fmt.Fprintf(&content, "name=%s\n", name)
	}
	fmt.Fprintf(&content, "baseurl=%s\n", c.BaseURL)
	if c.Enabled {
		content.WriteString("enabled=1\n")
	} else {
		content.WriteString("enabled=0\n")
	}
	if c.GPGCheck {
		content.WriteString("gpgcheck=1\n")
		if c.GPGKey != "" {
			fmt.Fprintf(&content, "gpgkey=%s\n", c.GPGKey)
		}
	} else {
		content.WriteString("gpgcheck=0\n")
	}
	if c.ModuleHotfixes {
		content.WriteString("module_hotfixes=1\n")
	}
	desired := content.String()

	// Idempotency: a byte-identical file means nothing to do.
	existing, err := m.fsm.ReadFile(ctx, repoFile)
	if err != nil {
		return Outcome{}, fmt.Errorf("read existing repo file: %w", err)
	}
	if string(existing) == desired {
		fmt.Fprintf(&log, "repository %s already up to date\n", name)
		return out(log.String(), false), nil
	}

	if err := m.fsm.WriteFile(ctx, repoFile, []byte(desired), fs.WriteOptions{Mode: 0o644}); err != nil {
		return Outcome{}, fmt.Errorf("write repo file: %w", err)
	}
	fmt.Fprintf(&log, "configured repository: %s\n", name)

	// rpm --import is idempotent (re-importing an existing key is a no-op). The
	// key is imported ONLY when signature checking is on: with gpgcheck=0 the
	// gpgkey= line is dropped from the .repo, so importing the key would silently
	// trust it system-wide while the repository itself verifies nothing — a trust
	// downgrade. Honor gpgcheck as the single switch and never import behind it.
	if c.GPGCheck && c.GPGKey != "" {
		res, kerr := m.runPriv(ctx, "rpm", pmexec.SeparatePositionals([]string{"--import"}, c.GPGKey)...)
		if res.Stdout != "" {
			log.WriteString(res.Stdout)
		}
		if kerr != nil {
			fmt.Fprintf(&log, "warning: failed to import GPG key: %v\n", kerr)
		}
	}

	res, rerr := m.runPriv(ctx, "dnf", "-y", "makecache", "--repo", name)
	if res.Stdout != "" {
		log.WriteString(res.Stdout)
	}
	if rerr != nil {
		fmt.Fprintf(&log, "warning: failed to refresh repo metadata: %v\n", rerr)
	}

	return out(log.String(), true), nil
}

// removeDnf deletes /etc/yum.repos.d/<name>.repo. Removing an already-absent
// repository is an idempotent no-op (Changed=false).
func (m *manager) removeDnf(ctx context.Context, name string) (Outcome, error) {
	repoFile := dnfRepoFile(name)
	var log strings.Builder
	exists, err := m.fsm.Exists(ctx, repoFile)
	if err != nil {
		return Outcome{}, fmt.Errorf("check repo file: %w", err)
	}
	if !exists {
		fmt.Fprintf(&log, "repository %s already absent\n", name)
		return out(log.String(), false), nil
	}
	if err := m.fsm.Remove(ctx, repoFile); err != nil {
		return Outcome{}, fmt.Errorf("remove repo file: %w", err)
	}
	fmt.Fprintf(&log, "removed repository: %s\n", name)
	return out(log.String(), true), nil
}
