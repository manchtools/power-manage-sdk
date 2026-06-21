package fs

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// DirEntry is one entry returned by Manager.ReadDir: the bare name (not a full
// path) and whether it is a directory. It is a minimal, backend-portable view —
// the escalated (find-based) listing cannot cheaply reproduce the full
// os.DirEntry / FileInfo surface, and the callers that enumerate a managed
// config directory need only the name plus is-it-a-directory. A symlink is
// reported with IsDir=false (its own type, not the target's), so a caller
// iterating regular files processes it like any other non-directory.
type DirEntry struct {
	Name  string
	IsDir bool
}

// ReadDir lists path's immediate entries.
//
// On the Direct backend (the deployed root agent) it reads the directory
// directly with os.ReadDir — root can traverse any directory, and this avoids a
// subprocess. On the escalated (Sudo/Doas) backend it shells `find` through the
// privilege backend so it can list directories the unprivileged caller cannot
// traverse, mirroring ReadFile/Exists.
//
// A MISSING directory returns a wrapped os.ErrNotExist (the same explicit-absence
// contract as ReadFile), NOT a silent empty listing — a caller that wants
// "absent → empty" opts in with errors.Is(err, fs.ErrNotExist). Any other failure
// (permission denied, a non-directory target) is returned as an error too — never
// silently reported as empty.
func (m *manager) ReadDir(ctx context.Context, path string) ([]DirEntry, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	if m.direct() {
		return readDirDirect(path)
	}
	return m.readDirEscalated(ctx, path)
}

// readDirDirect is the root path: os.ReadDir, which returns a wrapped
// os.ErrNotExist for a missing directory.
func readDirDirect(path string) ([]DirEntry, error) {
	osEntries, err := os.ReadDir(path)
	if err != nil {
		return nil, err // os.ReadDir wraps os.ErrNotExist for a missing dir
	}
	entries := make([]DirEntry, 0, len(osEntries))
	for _, e := range osEntries {
		entries = append(entries, DirEntry{Name: e.Name(), IsDir: e.IsDir()})
	}
	return entries, nil
}

// readDirEscalated is the privilege-backend path. It runs
//
//	find <path>/ -maxdepth 1 -mindepth 1 -printf '%y/%f\n'
//
// emitting one line per entry as "<type-char>/<basename>". A basename never
// contains '/', so the first '/' unambiguously separates the single type char
// from the name. (A pathological filename containing a newline would break the
// line framing; managed config directories never hold such names, and the
// Direct/root path — which the deployed agent always takes — handles them
// correctly via os.ReadDir.)
//
// The trailing slash is load-bearing: `find /file` on a REGULAR file exits 0
// with no output (which would otherwise read as a silently-empty directory),
// whereas `find /file/` reports ENOTDIR and exits non-zero. It makes the
// escalated path enforce the same "non-directory target is an error, never an
// empty listing" contract the Direct (os.ReadDir) path already honours.
func (m *manager) readDirEscalated(ctx context.Context, path string) ([]DirEntry, error) {
	res, err := m.runPriv(ctx, "find", path+"/", "-maxdepth", "1", "-mindepth", "1", "-printf", `%y/%f\n`)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		// ENOENT (missing dir) → explicit-absence contract; ENOTDIR (a regular
		// file) and any other failure → a real error, never a silent empty list.
		if isENOENTStderr(res.Stderr) {
			return nil, fmt.Errorf("read dir %s: %w", path, os.ErrNotExist)
		}
		return nil, cmdError("find", res)
	}
	var entries []DirEntry
	for _, line := range strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n") {
		if line == "" {
			continue
		}
		slash := strings.IndexByte(line, '/')
		if slash <= 0 || slash == len(line)-1 {
			continue // malformed: no type/name separator or empty name
		}
		entries = append(entries, DirEntry{Name: line[slash+1:], IsDir: line[:slash] == "d"})
	}
	return entries, nil
}
