package fs

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// ReadFile reads path's contents.
//
// On the Direct backend (the deployed root agent) it uses os.ReadFile — root can
// reach any file and this avoids a subprocess. On the escalated (Sudo/Doas)
// backend it shells `cat` through the privilege backend so it can read files in
// directories the unprivileged caller cannot traverse.
//
// A MISSING path returns a wrapped os.ErrNotExist (same as os.ReadFile), NOT a
// silent empty result — so a caller can tell "absent" from "present but empty"
// (the two are different states, and conflating them is a footgun). A caller that
// wants "absent → empty" opts in explicitly:
//
//	b, err := m.ReadFile(ctx, p)
//	if err != nil && !errors.Is(err, fs.ErrNotExist) { return err }
//	// b == nil here means the file was absent — treat as empty by choice
//
// An empty (but present) file returns (nil, nil). The returned bytes are the
// content verbatim; for newline-terminated content (every config file) they
// round-trip exactly with what WriteFile wrote, which the idempotency check
// depends on.
func (m *manager) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	if m.direct() {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err // a *PathError wrapping os.ErrNotExist for a missing path
		}
		if len(b) == 0 {
			return nil, nil // present but empty
		}
		return b, nil
	}
	res, err := m.runPriv(ctx, "cat", "--", path)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		if strings.Contains(res.Stderr, "No such file") {
			return nil, fmt.Errorf("read %s: %w", path, os.ErrNotExist)
		}
		return nil, cmdError("cat", res)
	}
	if res.Stdout == "" {
		return nil, nil // present but empty
	}
	return []byte(res.Stdout), nil
}

// Exists reports whether path exists. On the Direct backend it uses os.Stat (no
// subprocess); on the escalated backend it shells `test -e` so paths in
// directories not readable by the caller are visible. A genuine probe failure
// (runner/ctx error, or a non-not-exist stat error) is returned as an error so a
// probe that could not run is never silently treated as absence.
func (m *manager) Exists(ctx context.Context, path string) (bool, error) {
	if err := ValidatePath(path); err != nil {
		return false, err
	}
	if m.direct() {
		_, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
	res, err := m.runPriv(ctx, "test", "-e", path)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}
