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
	"time"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// validSystemdUnitName restricts systemd unit names to safe characters.
//
// Three design choices worth calling out:
//
//   - Leading '.' is rejected. Unit names starting with a dot aren't
//     valid systemd names and would look like hidden filesystem
//     entries; rejecting them here prevents any path-traversal-style
//     confusion downstream.
//
//   - Leading '-' IS allowed. systemd has legitimate unit names that
//     start with '-' (e.g. "-.mount", the root mount for '/'). Flag
//     injection at the argv level is prevented by always passing
//     unitName after an explicit "--" end-of-options separator in
//     every systemctl call in this file (defence in depth).
//
//   - `\xHH` hex-escape sequences are permitted so names produced by
//     systemd-escape(1) for paths or reserved characters flow through
//     validation unchanged (systemd.unit(5), "STRING ESCAPING FOR
//     INCLUSION IN UNIT NAMES").
//
// Suffixes cover every unit type systemd recognises, including the
// auto-generated .device units for hardware.
var validSystemdUnitName = regexp.MustCompile(`^(?:[a-zA-Z0-9@_:-]|\\x[0-9A-Fa-f]{2})(?:[a-zA-Z0-9@._:-]|\\x[0-9A-Fa-f]{2})*\.(service|socket|device|timer|mount|automount|swap|target|path|slice|scope)$`)

// systemctlQueryTimeout caps every is-enabled/is-active query so a
// hung unit (D-Bus stall, dependency loop, kernel oops) cannot pin
// the calling goroutine indefinitely. systemctl normally returns in
// well under a second; 30s leaves headroom for slow boot phases
// while still bounding worst-case wait. F023 in TECH_DEBT_AUDIT.md.
const systemctlQueryTimeout = 30 * time.Second

// systemctl returns non-zero exit codes for several "the unit is in
// state X" answers (is-enabled prints "disabled" and exits 1; is-active
// prints "inactive" and exits 3). Those are not query failures — the
// query succeeded and the answer is "no". A real query failure (D-Bus
// stall, dbus.service down, the timeout firing) leaves the output blank.
// Treat the "the answer is in stdout, the exit code just signals it"
// case as success and only surface an error when stdout is empty.
func runSystemctlQuery(unitName, verb string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlQueryTimeout)
	defer cancel()
	out, _, err := exec.QueryOutputCtx(ctx, "systemctl", verb, "--", unitName)
	trimmed := strings.TrimSpace(out)
	if err != nil && trimmed == "" {
		slog.Debug("systemctl query failed", "unit", unitName, "verb", verb, "error", err)
		return "", fmt.Errorf("systemctl %s %s: %w", verb, unitName, err)
	}
	return trimmed, nil
}

func statusSystemd(unitName string) (UnitStatus, error) {
	status := UnitStatus{}

	enabledStatus, err := runSystemctlQuery(unitName, "is-enabled")
	if err != nil {
		return UnitStatus{}, err
	}

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
	case "masked", "masked-runtime":
		// masked-runtime is the session-only variant produced by
		// `systemctl mask --runtime`; reporting both as Masked
		// matches operator intent.
		status.Masked = true
	}

	activeStatus, err := runSystemctlQuery(unitName, "is-active")
	if err != nil {
		return UnitStatus{}, err
	}
	status.Active = activeStatus == "active"

	return status, nil
}

func isEnabledSystemd(unitName string) (bool, error) {
	trimmed, err := runSystemctlQuery(unitName, "is-enabled")
	if err != nil {
		return false, err
	}
	// Only "enabled" and "enabled-runtime" count as explicitly enabled.
	// Static / indirect / generated units boot via dependencies but
	// cannot be toggled with systemctl enable/disable, so reporting
	// them as enabled here would mislead callers that use this result
	// to decide whether to call Enable().
	return trimmed == "enabled" || trimmed == "enabled-runtime", nil
}

func isMaskedSystemd(unitName string) (bool, error) {
	trimmed, err := runSystemctlQuery(unitName, "is-enabled")
	if err != nil {
		return false, err
	}
	// "masked-runtime" is `systemctl mask --runtime`'s session-only
	// variant — still masked from the caller's perspective.
	return trimmed == "masked" || trimmed == "masked-runtime", nil
}

func isActiveSystemd(unitName string) (bool, error) {
	trimmed, err := runSystemctlQuery(unitName, "is-active")
	if err != nil {
		return false, err
	}
	return trimmed == "active", nil
}

func daemonReloadSystemd(ctx context.Context) error {
	_, err := exec.Privileged(ctx, "systemctl", "daemon-reload")
	return err
}

func enableSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "enable", "--", unitName)
	return err
}

func disableSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "disable", "--", unitName)
	return err
}

func startSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "start", "--", unitName)
	return err
}

func stopSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "stop", "--", unitName)
	return err
}

func restartSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "restart", "--", unitName)
	return err
}

func maskSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "mask", "--", unitName)
	return err
}

func unmaskSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "unmask", "--", unitName)
	return err
}

func enableNowSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "enable", "--now", "--", unitName)
	return err
}

func disableNowSystemd(ctx context.Context, unitName string) error {
	if err := validateUnitNameSystemd(unitName); err != nil {
		return err
	}
	_, err := exec.Privileged(ctx, "systemctl", "disable", "--now", "--", unitName)
	return err
}

func validateUnitNameSystemd(unitName string) error {
	if !validSystemdUnitName.MatchString(unitName) {
		return fmt.Errorf("invalid systemd unit name %q: must not start with '.' and must match <name>.<type> where type is one of service, socket, device, timer, mount, automount, swap, target, path, slice, scope", unitName)
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
