// Package notify sends system-wide notifications to logged-in users.
// It uses wall for terminal sessions and notify-send for graphical sessions.
// All operations are best-effort — errors are logged but never returned,
// ensuring notifications never block the calling action.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// session represents a logged-in user session discovered via loginctl.
type session struct {
	id   string
	user string
	uid  int
	typ  string // "tty", "x11", "wayland", "mir"
}

// NotifyAll sends a notification to all logged-in users.
// Terminal users receive a wall broadcast, graphical users receive a desktop notification.
func NotifyAll(ctx context.Context, title, message string) {
	sendWall(ctx, fmt.Sprintf("%s: %s", title, message))
	sendDesktopNotifications(ctx, title, message, nil)
}

// NotifyUsers sends a notification to specific users.
// Only sessions belonging to the named users receive notifications.
func NotifyUsers(ctx context.Context, usernames []string, title, message string) {
	sendWall(ctx, fmt.Sprintf("%s: %s", title, message))

	filter := make(map[string]bool, len(usernames))
	for _, u := range usernames {
		filter[u] = true
	}
	sendDesktopNotifications(ctx, title, message, filter)
}

// sendWall broadcasts a message to all terminal sessions.
func sendWall(ctx context.Context, message string) {
	_, err := exec.SudoWithStdin(ctx, strings.NewReader(message), "wall")
	if err != nil {
		slog.Debug("wall notification failed", "error", err)
	}
}

// sendDesktopNotifications discovers graphical sessions and sends notify-send
// to each. If userFilter is non-nil, only sessions matching those usernames
// are notified.
func sendDesktopNotifications(ctx context.Context, title, message string, userFilter map[string]bool) {
	if _, err := osexec.LookPath("notify-send"); err != nil {
		slog.Debug("notify-send not available, skipping desktop notifications")
		return
	}

	sessions := listGraphicalSessions(ctx)
	for _, s := range sessions {
		if userFilter != nil && !userFilter[s.user] {
			continue
		}
		sendDesktopNotification(ctx, s, title, message)
	}
}

// listGraphicalSessions returns all active graphical login sessions.
func listGraphicalSessions(ctx context.Context) []session {
	result, err := exec.Sudo(ctx, "loginctl", "list-sessions", "--no-legend")
	if err != nil || result.ExitCode != 0 {
		slog.Debug("failed to list sessions", "error", err)
		return nil
	}

	var sessions []session
	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		sessionID := fields[0]

		// Query session type and user details
		info, err := exec.Sudo(ctx, "loginctl", "show-session", sessionID,
			"-p", "Type", "-p", "Name", "-p", "User", "--value")
		if err != nil || info.ExitCode != 0 {
			continue
		}

		lines := strings.Split(strings.TrimSpace(info.Stdout), "\n")
		if len(lines) < 3 {
			continue
		}

		typ := strings.TrimSpace(lines[0])
		user := strings.TrimSpace(lines[1])
		uid, _ := strconv.Atoi(strings.TrimSpace(lines[2]))

		if typ == "x11" || typ == "wayland" || typ == "mir" {
			sessions = append(sessions, session{
				id:   sessionID,
				user: user,
				uid:  uid,
				typ:  typ,
			})
		}
	}

	return sessions
}

// sendDesktopNotification sends a freedesktop notification to a single graphical session.
// It runs notify-send as the target user via runuser with the user's DBUS session.
func sendDesktopNotification(ctx context.Context, s session, title, message string) {
	dbusAddr := fmt.Sprintf("unix:path=/run/user/%d/bus", s.uid)

	// Check if the DBUS socket exists
	socketPath := fmt.Sprintf("/run/user/%d/bus", s.uid)
	if _, err := os.Stat(socketPath); err != nil {
		slog.Debug("DBUS socket not found, skipping desktop notification",
			"user", s.user, "path", socketPath)
		return
	}

	// Use runuser to execute notify-send as the target user.
	// The agent has sudo access to bash, which gives us root,
	// and runuser (part of util-linux) switches to the target user.
	script := fmt.Sprintf(
		`DBUS_SESSION_BUS_ADDRESS=%s runuser -u %s -- notify-send -u critical -a "Power Manage" -i dialog-warning %q %q`,
		dbusAddr, s.user, title, message,
	)

	result, err := exec.Sudo(ctx, "bash", "-c", script)
	if err != nil || (result != nil && result.ExitCode != 0) {
		slog.Debug("desktop notification failed",
			"user", s.user, "session", s.id, "error", err)
	}
}
