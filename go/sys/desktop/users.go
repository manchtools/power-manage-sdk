package desktop

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// HomeUsers enumerates every Linux account on the host whose home
// directory lives directly under <homeRoot>/<name> (homeRoot defaults to
// /home; override with WithHomeRoot). For each subdir we call os/user.Lookup
// to confirm a real account exists (catches stale `userdel`-without-`-r`
// directories) and to recover the canonical UID/GID/Home from passwd or NSS.
//
// This is the primitive for "do something for every offline user" —
// the install / online path uses ActiveSessions, the uninstall /
// passive path (and similar "clean up every user's home" sweeps)
// uses HomeUsers.
//
// Returns an empty slice — not an error — when the home root is missing or
// empty. Returns an error only when it exists but cannot be read (permission
// denied, IO error). Per-user lookup failures are silently skipped: a
// non-resolving home dir means a stale entry, not a fault we want to surface.
//
// The ctx is accepted for shape-uniformity and future cancellation; the
// enumeration itself is local filesystem + passwd lookups.
//
// Limitations (intentional, documented for callers picking the
// right helper):
//   - Custom $HOME paths outside the home root (LDAP /home/<domain>/<user>,
//     /auto.home/<user>, etc.) are missed. Those layouts are
//     uncommon on managed Linux endpoints; passwd-iterating
//     wouldn't catch them either if the home dir is auto-mounted
//     on first access.
//   - Encrypted homes (ecryptfs) appear as a single <homeRoot>/<name>
//     dir but the contents are unreadable without the user's
//     session. Per-user state inside the encrypted volume is
//     invisible to a sweep that runs while the user is offline.
func (m *manager) HomeUsers(ctx context.Context) ([]Session, error) {
	entries, err := os.ReadDir(m.homeRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", m.homeRoot, err)
	}

	out := make([]Session, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Skip dot-prefixed directories (.ecryptfs, .pwd.lock, etc.)
		// and the conventional /home/lost+found left by fsck.
		name := e.Name()
		if name == "" || name[0] == '.' || name == "lost+found" {
			continue
		}
		s, ok := homeUserFor(name)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

// homeUserFor builds a Session for the given <homeRoot>/<name> subdir if
// it resolves to a real account. Returns (zero, false) on any lookup
// failure — callers treat that as "not a real user, skip silently."
func homeUserFor(name string) (Session, bool) {
	u, err := lookupUser(name)
	if err != nil {
		return Session{}, false
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return Session{}, false
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return Session{}, false
	}
	// Trust the canonical home from the lookup over the directory
	// name — a system with /etc/skel symlinks or unusual NSS modules
	// can have <homeRoot>/<name> exist while the canonical home is
	// elsewhere; using the lookup result keeps us aligned with what
	// runuser will see.
	return Session{
		Username:   u.Username,
		UID:        uid,
		GID:        gid,
		Home:       u.HomeDir,
		RuntimeDir: "/run/user/" + u.Uid,
	}, true
}

// UsersWithFlatpakInstall returns the subset of HomeUsers whose
// per-user Flatpak repository contains the named app. This is the
// authoritative answer to "which offline users need this app
// uninstalled from their per-user install" — covers users who
// installed at a previous management cycle and aren't currently
// signed in.
//
// Errors:
//   - returns an error if appID is empty (caller bug — would otherwise
//     glob "every per-user flatpak install on the box")
//   - propagates the error from HomeUsers when the home root itself is
//     unreadable (permission denied, IO error). The caller treats
//     that as fail-the-whole-uninstall, since we can't say the action
//     converged when we can't even enumerate the candidate set.
//
// Per-user os.Stat failures inside the loop (e.g. an unreadable
// $HOME for one specific account) are silently skipped — they
// represent "we can't see whether this user has it installed," and
// the next reconciliation tick re-checks once the access issue
// resolves. The caller still logs per-user uninstall errors from the
// returned set itself.
func (m *manager) UsersWithFlatpakInstall(ctx context.Context, appID string) ([]Session, error) {
	if appID == "" {
		return nil, fmt.Errorf("UsersWithFlatpakInstall: appID required")
	}
	users, err := m.HomeUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(users))
	for _, u := range users {
		// Per-user installs land under
		// $HOME/.local/share/flatpak/app/<appID>/. Existence of the
		// directory is the cheapest possible "is it installed" check
		// — a full `flatpak --user info` invocation per user would
		// be 10-100× slower on a box with many accounts.
		appDir := filepath.Join(u.Home, ".local", "share", "flatpak", "app", appID)
		if _, err := os.Stat(appDir); err != nil {
			continue
		}
		out = append(out, u)
	}
	return out, nil
}
