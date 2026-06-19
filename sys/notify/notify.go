// Package notify sends system-wide notifications to logged-in users through an
// injected exec.Runner. It uses wall for terminal sessions and notify-send for
// graphical sessions. Methods return an aggregated error of every delivery that
// ran and failed; an absent capability (no notify-send, no D-Bus socket, no
// sessions) is a graceful skip, not an error. The SDK surfaces failures; the
// caller decides whether to ignore them (notifications need not block an action).
//
//	r, _ := exec.NewRunner(exec.Sudo)
//	n, _ := notify.New(r)
//	n.NotifyAll(ctx, "Maintenance", "Reboot in 5 minutes")
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// Seams: notify-send presence + the per-user D-Bus socket check. Overridable from
// tests so desktop-notification dispatch can be exercised without a real session.
var (
	lookPath   = osexec.LookPath
	statSocket = os.Stat
)

// session represents a logged-in user session discovered via loginctl.
type session struct {
	id   string
	user string
	uid  int
	typ  string // "tty", "x11", "wayland", "mir"
}

// Manager sends notifications to logged-in users. Methods return an aggregated
// error of deliveries that ran and failed; an absent capability is a graceful
// skip (nil).
type Manager interface {
	// NotifyAll notifies every logged-in user: a wall broadcast to terminal
	// sessions and a desktop notification to graphical ones. It returns an
	// aggregated error of every attempt that ran and failed; an absent capability
	// (no notify-send, no D-Bus socket, no sessions) is a graceful skip, not an
	// error. The SDK surfaces failures; the caller decides whether to ignore them.
	NotifyAll(ctx context.Context, title, message string) error
	// NotifyUsers notifies the named users only (wall still broadcasts, since it
	// has no per-user target). Error semantics match NotifyAll.
	NotifyUsers(ctx context.Context, usernames []string, title, message string) error
}

// New returns a Manager driven by runner. A nil runner is rejected.
func New(runner exec.Runner) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("notify: %w", exec.ErrRunnerRequired)
	}
	return &notifier{r: runner}, nil
}

type notifier struct {
	r exec.Runner
}

func (n *notifier) NotifyAll(ctx context.Context, title, message string) error {
	return errors.Join(
		n.sendWall(ctx, fmt.Sprintf("%s: %s", title, message)),
		n.sendDesktopNotifications(ctx, title, message, nil),
	)
}

func (n *notifier) NotifyUsers(ctx context.Context, usernames []string, title, message string) error {
	filter := make(map[string]bool, len(usernames))
	for _, u := range usernames {
		filter[u] = true
	}
	return errors.Join(
		n.sendWall(ctx, fmt.Sprintf("%s: %s", title, message)),
		n.sendDesktopNotifications(ctx, title, message, filter),
	)
}

// sendWall broadcasts a message to all terminal sessions via wall (stdin). A
// failed broadcast (runner error or non-zero exit) is returned, not swallowed.
func (n *notifier) sendWall(ctx context.Context, message string) error {
	res, err := n.r.Run(ctx, exec.Command{
		Name:     "wall",
		Stdin:    strings.NewReader(message),
		Escalate: true,
	})
	if err != nil {
		return fmt.Errorf("wall notification: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("wall notification failed: exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// sendDesktopNotifications discovers graphical sessions and sends notify-send to
// each. With a non-nil userFilter only matching usernames are notified. It
// returns the aggregated errors of deliveries that ran and failed; an absent
// notify-send is a graceful skip (nil), not a failure.
func (n *notifier) sendDesktopNotifications(ctx context.Context, title, message string, userFilter map[string]bool) error {
	if _, err := lookPath("notify-send"); err != nil {
		slog.Warn("notify-send not available, skipping desktop notifications")
		return nil
	}
	sessions, err := n.listGraphicalSessions(ctx)
	if err != nil {
		return err
	}
	slog.Info("discovered graphical sessions for desktop notification", "count", len(sessions))
	var errs []error
	for _, s := range sessions {
		if userFilter != nil && !userFilter[s.user] {
			continue
		}
		if e := n.sendDesktopNotification(ctx, s, title, message); e != nil {
			errs = append(errs, e)
		}
	}
	return errors.Join(errs...)
}

// listGraphicalSessions returns all active graphical login sessions. A failed
// enumeration is an error (we couldn't determine who to notify); a single
// session whose details can't be read is skipped (best-effort per session).
func (n *notifier) listGraphicalSessions(ctx context.Context) ([]session, error) {
	res, err := n.r.Run(ctx, exec.Command{Name: "loginctl", Args: []string{"list-sessions", "--no-legend"}, Escalate: true})
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("list sessions failed: exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	var sessions []session
	for _, sessionID := range parseLoginctlListSessions(res.Stdout) {
		// Without --value loginctl prints Key=Value lines so we parse by name —
		// D-Bus emission order isn't documented as stable, so positional parsing
		// would silently misassign fields across systemd versions.
		info, err := n.r.Run(ctx, exec.Command{
			Name:     "loginctl",
			Args:     []string{"show-session", sessionID, "-p", "Type", "-p", "Name", "-p", "User"},
			Escalate: true,
		})
		if err != nil || info.ExitCode != 0 {
			continue
		}
		s, ok := parseLoginctlShowSession(sessionID, info.Stdout)
		if !ok {
			continue
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

// parseLoginctlListSessions extracts session IDs from `loginctl list-sessions
// --no-legend` output. The first whitespace-separated field is the session ID;
// lines with fewer than three fields are skipped. Pure-function shape so it can be
// tested without shelling out (F026 in TECH_DEBT_AUDIT.md).
func parseLoginctlListSessions(stdout string) []string {
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ids = append(ids, fields[0])
	}
	return ids
}

// parseLoginctlShowSession parses `loginctl show-session <id> -p Type -p Name -p
// User` output into a session struct, by property name (loginctl emits Key=Value
// in D-Bus dictionary order, not -p order). Returns (session, false) when any of
// Type / Name / User is missing, User isn't a numeric uid, Name is empty, or Type
// isn't graphical (x11 / wayland / mir).
func parseLoginctlShowSession(sessionID, stdout string) (session, bool) {
	props := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		props[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	typ := props["Type"]
	user := props["Name"]
	uidStr, hasUID := props["User"]
	if !hasUID || user == "" {
		return session{}, false
	}
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return session{}, false
	}
	if typ != "x11" && typ != "wayland" && typ != "mir" {
		return session{}, false
	}
	return session{id: sessionID, user: user, uid: uid, typ: typ}, true
}

// sendDesktopNotification sends a freedesktop notification to a single graphical
// session, running notify-send as the target user (via runuser) with the user's
// D-Bus session address. Each argument is passed separately to avoid shell
// injection.
func (n *notifier) sendDesktopNotification(ctx context.Context, s session, title, message string) error {
	socketPath := fmt.Sprintf("/run/user/%d/bus", s.uid)
	if _, err := statSocket(socketPath); err != nil {
		// No D-Bus session bus for this user — nothing to deliver to; graceful skip.
		slog.Warn("DBUS socket not found, skipping desktop notification", "user", s.user, "path", socketPath)
		return nil
	}
	dbusAddr := "unix:path=" + socketPath

	res, err := n.r.Run(ctx, exec.Command{
		Name: "env",
		Args: []string{
			"DBUS_SESSION_BUS_ADDRESS=" + dbusAddr,
			"runuser", "-u", s.user, "--",
			"notify-send", "-u", "critical", "-a", "Power Manage", "-i", "dialog-warning",
			title, message,
		},
		Escalate: true,
	})
	if err != nil {
		return fmt.Errorf("desktop notification to %s: %w", s.user, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("desktop notification to %s failed: exit %d: %s", s.user, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}
