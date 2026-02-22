// Package systemd provides systemd unit management utilities for Linux systems.
//
// Control operations (Enable, Start, Stop, etc.) use sudo for privilege
// escalation. Query operations (Status, IsEnabled, IsActive) run as the
// current user since systemctl status queries don't require root.
package systemd

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// validUnitName restricts systemd unit names to safe characters,
// preventing path traversal attacks (e.g. "../../../etc/shadow").
var validUnitName = regexp.MustCompile(`^[a-zA-Z0-9@._:-]+\.(service|socket|timer|mount|automount|swap|target|path|slice|scope)$`)

// UnitStatus represents the current status of a systemd unit.
type UnitStatus struct {
	Enabled bool
	Active  bool
	Masked  bool
	Static  bool
}

// =============================================================================
// Systemd Unit State Queries
// =============================================================================

// Status retrieves the complete status of a systemd unit.
func Status(unitName string) UnitStatus {
	status := UnitStatus{}

	// Check enabled state
	out, _, _ := exec.QueryOutput("systemctl", "is-enabled", unitName)
	enabledStatus := strings.TrimSpace(out)

	switch enabledStatus {
	case "enabled", "enabled-runtime":
		status.Enabled = true
	case "static", "indirect", "generated":
		status.Enabled = true
		status.Static = true
	case "masked":
		status.Masked = true
	}

	// Check active state
	out, _, _ = exec.QueryOutput("systemctl", "is-active", unitName)
	status.Active = strings.TrimSpace(out) == "active"

	return status
}

// IsEnabled checks if a systemd unit is enabled or in a state where
// enabling is not needed (static, indirect, generated units).
func IsEnabled(unitName string) bool {
	out, _, _ := exec.QueryOutput("systemctl", "is-enabled", unitName)
	status := strings.TrimSpace(out)
	switch status {
	case "enabled", "enabled-runtime":
		return true
	case "static", "indirect", "generated":
		return true
	default:
		return false
	}
}

// IsMasked checks if a systemd unit is masked.
func IsMasked(unitName string) bool {
	out, _, _ := exec.QueryOutput("systemctl", "is-enabled", unitName)
	return strings.TrimSpace(out) == "masked"
}

// IsActive checks if a systemd unit is currently active (running).
func IsActive(unitName string) bool {
	out, _, _ := exec.QueryOutput("systemctl", "is-active", unitName)
	return strings.TrimSpace(out) == "active"
}

// =============================================================================
// Systemd Unit Control Operations
// =============================================================================

// DaemonReload runs systemctl daemon-reload to reload systemd configuration.
func DaemonReload(ctx context.Context) error {
	_, err := exec.Sudo(ctx, "systemctl", "daemon-reload")
	return err
}

// Enable enables a systemd unit.
func Enable(ctx context.Context, unitName string) error {
	_, err := exec.Sudo(ctx, "systemctl", "enable", unitName)
	return err
}

// Disable disables a systemd unit.
func Disable(ctx context.Context, unitName string) error {
	_, err := exec.Sudo(ctx, "systemctl", "disable", unitName)
	return err
}

// Start starts a systemd unit.
func Start(ctx context.Context, unitName string) error {
	_, err := exec.Sudo(ctx, "systemctl", "start", unitName)
	return err
}

// Stop stops a systemd unit.
func Stop(ctx context.Context, unitName string) error {
	_, err := exec.Sudo(ctx, "systemctl", "stop", unitName)
	return err
}

// Restart restarts a systemd unit.
func Restart(ctx context.Context, unitName string) error {
	_, err := exec.Sudo(ctx, "systemctl", "restart", unitName)
	return err
}

// Mask masks a systemd unit, preventing it from being started.
func Mask(ctx context.Context, unitName string) error {
	_, err := exec.Sudo(ctx, "systemctl", "mask", unitName)
	return err
}

// Unmask unmasks a systemd unit.
func Unmask(ctx context.Context, unitName string) error {
	_, err := exec.Sudo(ctx, "systemctl", "unmask", unitName)
	return err
}

// EnableNow enables and starts a systemd unit.
func EnableNow(ctx context.Context, unitName string) error {
	_, err := exec.Sudo(ctx, "systemctl", "enable", "--now", unitName)
	return err
}

// DisableNow disables and stops a systemd unit.
func DisableNow(ctx context.Context, unitName string) error {
	_, err := exec.Sudo(ctx, "systemctl", "disable", "--now", unitName)
	return err
}

// =============================================================================
// Systemd Unit File Operations
// =============================================================================

// ValidateUnitName checks if a systemd unit name is safe (no path traversal).
func ValidateUnitName(unitName string) error {
	if !validUnitName.MatchString(unitName) {
		return fmt.Errorf("invalid systemd unit name %q: must match [a-zA-Z0-9@._:-]+.<type>", unitName)
	}
	return nil
}

// WriteUnit writes a systemd unit file to /etc/systemd/system atomically
// with mode 0644, owned by root:root.
func WriteUnit(ctx context.Context, unitName, content string) error {
	if err := ValidateUnitName(unitName); err != nil {
		return err
	}
	unitPath := "/etc/systemd/system/" + unitName
	return fs.WriteFileAtomic(ctx, unitPath, content, "0644", "root", "root")
}

// RemoveUnit removes a systemd unit file from /etc/systemd/system.
// This is a best-effort operation.
func RemoveUnit(ctx context.Context, unitName string) {
	if ValidateUnitName(unitName) != nil {
		return
	}
	unitPath := "/etc/systemd/system/" + unitName
	fs.Remove(ctx, unitPath)
}
