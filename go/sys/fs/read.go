package fs

import (
	"context"
	"strings"
)

// ReadFile reads path's contents via the privilege backend (cat), so it can
// read files in directories the caller cannot traverse. A path that does not
// exist (or an empty file) yields (nil, nil): absence is reported as empty
// content, matching the long-standing contract config-management callers rely on.
//
// ReadFile returns the Runner's cat stdout verbatim (no re-add, no strip). For
// newline-terminated content — every config file — the bytes round-trip exactly
// with what WriteFile wrote, which the idempotency check depends on. (The Runner
// normalizes a final line that lacks a newline by appending one, so a file with
// no trailing newline reads back with one; managed text files always end in a
// newline, so this does not affect them.)
func (m *manager) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	res, err := m.runPriv(ctx, "cat", "--", path)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		if strings.Contains(res.Stderr, "No such file") {
			return nil, nil
		}
		return nil, cmdError("cat", res)
	}
	if res.Stdout == "" {
		return nil, nil
	}
	return []byte(res.Stdout), nil
}

// Exists reports whether path exists, probing through the privilege backend
// (test -e) so paths in directories not readable by the caller are visible. A
// non-zero exit means "absent"; a runner/ctx failure is returned as an error so
// a probe that could not run is never silently treated as absence.
func (m *manager) Exists(ctx context.Context, path string) (bool, error) {
	if err := ValidatePath(path); err != nil {
		return false, err
	}
	res, err := m.runPriv(ctx, "test", "-e", path)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}
