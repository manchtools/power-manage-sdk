package service

// Systemd backend implementation. These functions are unexported and
// reached through service.go's dispatch; callers should use the public
// API (Enable, Start, …) rather than importing these directly.

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// validSystemdUnitName restricts systemd unit names to safe characters,
// preventing path traversal attacks (e.g. "../../../etc/shadow") and
// flag injection (a leading '-' would be parsed by systemctl as an
// option rather than a unit name).
var validSystemdUnitName = regexp.MustCompile(`^[a-zA-Z0-9@._:][a-zA-Z0-9@._:-]*\.(service|socket|timer|mount|automount|swap|target|path|slice|scope)$`)

func statusSystemd(unitName string) UnitStatus {
	status := UnitStatus{}

	out, _, err := exec.QueryOutput("systemctl", "is-enabled", unitName)
	if err != nil {
		slog.Debug("systemctl is-enabled failed", "unit", unitName, "error", err)
	}
	enabledStatus := strings.TrimSpace(out)

	// systemctl distinguishes explicitly-enabled units ("enabled",
	// "enabled-runtime") from units that happen to start at boot via
	// dependencies ("static", "indirect", "generated"). Callers asking
	// "is this explicitly enabled?" should get false for the latter
	// group — `systemctl enable` on a static unit fails with "has no
	// [Install] section". Callers that need "will it run at boot?"
	// should check Enabled || Static.
	switch enabledStatus {
	case "enabled", "enabled-runtime":
		status.Enabled = true
	case "static", "indirect", "generated":
		status.Static = true
	case "masked":
		status.Masked = true
	}

	out, _, err = exec.QueryOutput("systemctl", "is-active", unitName)
	if err != nil {
		slog.Debug("systemctl is-active failed", "unit", unitName, "error", err)
	}
	status.Active = strings.TrimSpace(out) == "active"

	return status
}

func isEnabledSystemd(unitName string) bool {
	out, _, err := exec.QueryOutput("systemctl", "is-enabled", unitName)
	if err != nil {
		slog.Debug("systemctl is-enabled failed", "unit", unitName, "error", err)
	}
	// Only "enabled" and "enabled-runtime" count as explicitly enabled.
	// Static / indirect / generated units boot via dependencies but
	// cannot be toggled with systemctl enable/disable, so reporting
	// them as enabled here would mislead callers that use this result
	// to decide whether to call Enable().
	trimmed := strings.TrimSpace(out)
	return trimmed == "enabled" || trimmed == "enabled-runtime"
}

func isMaskedSystemd(unitName string) bool {
	out, _, err := exec.QueryOutput("systemctl", "is-enabled", unitName)
	if err != nil {
		slog.Debug("systemctl is-enabled failed", "unit", unitName, "error", err)
	}
	return strings.TrimSpace(out) == "masked"
}

func isActiveSystemd(unitName string) bool {
	out, _, err := exec.QueryOutput("systemctl", "is-active", unitName)
	if err != nil {
		slog.Debug("systemctl is-active failed", "unit", unitName, "error", err)
	}
	return strings.TrimSpace(out) == "active"
}

func daemonReloadSystemd(ctx context.Context) error {
	_, err := exec.Privileged(ctx, "systemctl", "daemon-reload")
	return err
}

func enableSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "enable", unitName)
	return err
}

func disableSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "disable", unitName)
	return err
}

func startSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "start", unitName)
	return err
}

func stopSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "stop", unitName)
	return err
}

func restartSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "restart", unitName)
	return err
}

func maskSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "mask", unitName)
	return err
}

func unmaskSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "unmask", unitName)
	return err
}

func enableNowSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "enable", "--now", unitName)
	return err
}

func disableNowSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "disable", "--now", unitName)
	return err
}

func validateUnitNameSystemd(unitName string) error {
	if !validSystemdUnitName.MatchString(unitName) {
		return fmt.Errorf("invalid systemd unit name %q: must start with [a-zA-Z0-9@._:] and match <name>.<type>", unitName)
	}
	return nil
}

func writeUnitSystemd(ctx context.Context, unitName, content string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	unitPath := "/etc/systemd/system/" + unitName
	return fs.WriteFileAtomic(ctx, unitPath, content, "0644", "root", "root")
}

func removeUnitSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	unitPath := "/etc/systemd/system/" + unitName
	if err := fs.RemoveStrict(ctx, unitPath); err != nil {
		return fmt.Errorf("remove systemd unit %s: %w", unitPath, err)
	}
	return nil
}
