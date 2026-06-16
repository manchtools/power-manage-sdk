package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// systemd is the systemctl-backed Manager. Every operation runs through the
// injected Runner — query verbs unprivileged, mutations escalated — so the
// package is unit-testable with exectest.FakeRunner.
type systemd struct {
	r exec.Runner
}

// validSystemdUnitName restricts unit names to safe characters.
//
//   - Leading '.' is rejected (not a valid systemd name; avoids hidden-file
//     confusion).
//   - Leading '-' IS allowed (legit units like "-.mount"); argv flag injection
//     is independently prevented by the "--" end-of-options separator on every
//     systemctl call.
//   - `\xHH` escapes are permitted so systemd-escape(1) output validates as-is.
//
// Suffixes cover every unit type systemd recognises.
var validSystemdUnitName = regexp.MustCompile(`^(?:[a-zA-Z0-9@_:-]|\\x[0-9A-Fa-f]{2})(?:[a-zA-Z0-9@._:-]|\\x[0-9A-Fa-f]{2})*\.(service|socket|device|timer|mount|automount|swap|target|path|slice|scope)$`)

// ValidateUnitName reports whether unit is a safe, well-formed systemd unit name.
func ValidateUnitName(unit string) error {
	if !validSystemdUnitName.MatchString(unit) {
		return fmt.Errorf("invalid systemd unit name %q: must not start with '.' and must match <name>.<type> where type is one of service, socket, device, timer, mount, automount, swap, target, path, slice, scope", unit)
	}
	return nil
}

// validSystemctlOutputs whitelists the answers each query verb may print.
// Anything else (most importantly "not-found" / a blank line / a D-Bus stall) is
// a query FAILURE, so callers can tell "definitely disabled" from "couldn't
// tell". Lists are taken from systemctl(1).
var validSystemctlOutputs = map[string]map[string]struct{}{
	"is-enabled": {
		"enabled": {}, "enabled-runtime": {}, "linked": {}, "linked-runtime": {},
		"alias": {}, "masked": {}, "masked-runtime": {}, "static": {},
		"indirect": {}, "disabled": {}, "generated": {}, "transient": {},
	},
	"is-active": {
		"active": {}, "reloading": {}, "inactive": {},
		"failed": {}, "activating": {}, "deactivating": {},
	},
}

// query runs an unprivileged `systemctl <verb> -- <unit>` and returns the
// trimmed, whitelist-validated state. A non-zero exit is NOT a failure on its
// own (is-enabled prints "disabled" and exits 1; is-active prints "inactive" and
// exits 3) — only an exec error or an off-whitelist/blank output is. The caller
// validates the unit name.
func (s *systemd) query(ctx context.Context, unit, verb string) (string, error) {
	ctx, cancel := ensureCtx(ctx)
	defer cancel()
	res, err := s.r.Run(ctx, exec.Command{Name: "systemctl", Args: []string{verb, "--", unit}})
	if err != nil {
		return "", fmt.Errorf("systemctl %s %s: %w", verb, unit, err)
	}
	trimmed := strings.TrimSpace(res.Stdout)
	allowed, known := validSystemctlOutputs[verb]
	if !known {
		return "", fmt.Errorf("systemctl %s: unsupported query verb", verb)
	}
	if _, ok := allowed[trimmed]; !ok {
		return "", fmt.Errorf("systemctl %s %s: unrecognised output %q (exit %d)", verb, unit, trimmed, res.ExitCode)
	}
	return trimmed, nil
}

// mutate runs an escalated systemctl command, mapping a non-zero exit to a
// *exec.CommandError.
func (s *systemd) mutate(ctx context.Context, args ...string) error {
	res, err := s.r.Run(ctx, exec.Command{Name: "systemctl", Args: args, Escalate: true})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return &exec.CommandError{Name: "systemctl", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}

// --- Queries ---------------------------------------------------------------

func (s *systemd) Status(ctx context.Context, unit string) (UnitStatus, error) {
	if err := ValidateUnitName(unit); err != nil {
		return UnitStatus{}, err
	}
	var status UnitStatus
	enabled, err := s.query(ctx, unit, "is-enabled")
	if err != nil {
		return UnitStatus{}, err
	}
	switch enabled {
	case "enabled", "enabled-runtime":
		status.Enabled = true
	case "static", "indirect", "generated":
		status.Static = true
	case "masked", "masked-runtime":
		status.Masked = true
	}
	active, err := s.query(ctx, unit, "is-active")
	if err != nil {
		return UnitStatus{}, err
	}
	status.Active = active == "active"
	return status, nil
}

func (s *systemd) IsEnabled(ctx context.Context, unit string) (bool, error) {
	if err := ValidateUnitName(unit); err != nil {
		return false, err
	}
	// Only "enabled"/"enabled-runtime" count: static/indirect/generated units
	// boot via dependencies but cannot be toggled with systemctl enable/disable.
	out, err := s.query(ctx, unit, "is-enabled")
	if err != nil {
		return false, err
	}
	return out == "enabled" || out == "enabled-runtime", nil
}

func (s *systemd) IsMasked(ctx context.Context, unit string) (bool, error) {
	if err := ValidateUnitName(unit); err != nil {
		return false, err
	}
	out, err := s.query(ctx, unit, "is-enabled")
	if err != nil {
		return false, err
	}
	return out == "masked" || out == "masked-runtime", nil
}

func (s *systemd) IsActive(ctx context.Context, unit string) (bool, error) {
	if err := ValidateUnitName(unit); err != nil {
		return false, err
	}
	out, err := s.query(ctx, unit, "is-active")
	if err != nil {
		return false, err
	}
	return out == "active", nil
}

// --- Mutations -------------------------------------------------------------

func (s *systemd) Enable(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return s.mutate(ctx, "enable", "--", unit)
}

func (s *systemd) Disable(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return s.mutate(ctx, "disable", "--", unit)
}

func (s *systemd) EnableNow(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return s.mutate(ctx, "enable", "--now", "--", unit)
}

func (s *systemd) DisableNow(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return s.mutate(ctx, "disable", "--now", "--", unit)
}

func (s *systemd) Start(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return s.mutate(ctx, "start", "--", unit)
}

func (s *systemd) Stop(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return s.mutate(ctx, "stop", "--", unit)
}

func (s *systemd) Restart(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return s.mutate(ctx, "restart", "--", unit)
}

func (s *systemd) Mask(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return s.mutate(ctx, "mask", "--", unit)
}

func (s *systemd) Unmask(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return s.mutate(ctx, "unmask", "--", unit)
}

func (s *systemd) DaemonReload(ctx context.Context) error {
	return s.mutate(ctx, "daemon-reload")
}

// --- Unit files ------------------------------------------------------------

func (s *systemd) WriteUnit(ctx context.Context, unit, content string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	return writeFileAtomic(ctx, "/etc/systemd/system/"+unit, content, "0644", "root", "root")
}

func (s *systemd) RemoveUnit(ctx context.Context, unit string) error {
	if err := ValidateUnitName(unit); err != nil {
		return err
	}
	path := "/etc/systemd/system/" + unit
	if err := removeStrict(ctx, path); err != nil {
		return fmt.Errorf("remove systemd unit %s: %w", path, err)
	}
	return nil
}
