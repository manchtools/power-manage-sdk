// Package fs provides privileged filesystem operations for Linux system
// management, driven by an injected exec.Runner rather than a process-global
// privilege backend.
//
// A Manager is built over a Runner; the backend the Runner reports selects the
// privilege strategy per operation, with no global state and full unit-test
// coverage via exectest.FakeRunner:
//
//	r, _ := exec.NewRunner(exec.Direct) // the agent runs as root; elsewhere Sudo/Doas
//	m, err := fs.New(r)
//	if err != nil { ... }
//	if err := m.WriteFile(ctx, "/etc/app.conf", data, fs.WriteOptions{Mode: 0o644, Owner: "root", Group: "root"}); err != nil { ... }
//
// When the Runner reports the Direct backend — the deployed root agent — writes
// and recursive deletes take the TOCTOU-safe, fd-anchored path (O_NOFOLLOW
// opens, RENAME_NOREPLACE, openat/unlinkat walks). Under Sudo/Doas (a non-root
// caller, e.g. CI or a dev tool) the same operations shell through the privilege
// backend (tee/mv/rm/chmod/chown); that path is not symlink-safe, but the
// security-relevant consumer — the root agent — never takes it.
//
// The fd-anchored primitives (OpenRealDir, FchownNoFollow,
// SetDirPermissionsNoFollow, ResolveOwnership) and the path predicates
// (ValidatePath, ResolveAndValidatePath, IsProtectedPath,
// IsUnderProtectedPrefix, AssertRealDir) remain exported free functions: they
// take no privilege and callers (notably the agent's directory action) use them
// directly.
package fs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// ErrInvalidPath is returned by ValidatePath when the supplied path would be
// unsafe to pass as a positional argument to a privileged command (empty,
// contains a NUL byte, or starts with `-` and would be interpreted as a flag).
var ErrInvalidPath = errors.New("invalid filesystem path")

// ErrUnsafeParentDir is returned by the escalated (sudo/doas) WriteFile when the
// target's parent directory is writable by a non-root user — a directory where
// an attacker could plant a symlink and redirect a root write. The escalated
// path fails closed rather than write into such a directory. (The Direct/root
// path is fd-anchored and does not need this; it is only the shell-based
// escalated path, used by non-root callers, that cannot openat the target.)
var ErrUnsafeParentDir = errors.New("parent directory is writable by non-root")

// ErrUnsafeMode is returned when a privileged file operation is asked to set a
// setuid or setgid bit. A managed config write must never create a privileged
// executable: a setuid-root binary the agent drops is a direct local-root
// privilege-escalation primitive, so the operation fails closed before any
// command runs. The sticky bit and ordinary permission bits are unaffected.
var ErrUnsafeMode = errors.New("setuid/setgid mode is not permitted")

// ErrProtectedTarget is returned when a recursive ownership change (chown -R)
// targets a whole top-level system directory (`/`, `/etc`, `/usr`, `/home`,
// `/root`, …). Recursively re-owning such a tree is a destructive
// privilege-escalation vector (e.g. handing an attacker ownership of every file
// under `/`), so it fails closed before chown runs. A managed subdirectory
// (e.g. /home/alice) and single-file SetOwnership are unaffected.
var ErrProtectedTarget = errors.New("recursive ownership change of a protected system tree is not permitted")

// WriteOptions configures a Manager.WriteFile (or Copy) call.
type WriteOptions struct {
	// Mode is the file mode applied before the file is reachable by name. Zero
	// means 0644 (the conventional mode for a managed config file), so the
	// resulting inode always carries a deterministic mode rather than depending
	// on the process umask.
	Mode os.FileMode
	// Owner and Group set the file's ownership. Either may be empty; both empty
	// leaves ownership at the OS default.
	Owner, Group string
	// Backup, when non-empty, copies the existing file at the destination to
	// this path before the new content replaces it (no-op if the destination
	// does not yet exist). The copy is taken crash-safely — the destination is
	// never left absent — which the agent's self-update relies on.
	Backup string
}

// MkdirOptions configures a Manager.Mkdir call.
type MkdirOptions struct {
	// Mode is applied to the created directory. Zero leaves the OS default
	// (mkdir's mode minus umask) in place.
	Mode os.FileMode
	// Owner and Group set the directory's ownership. Either may be empty.
	Owner, Group string
	// Recursive creates parent directories as needed (mkdir -p).
	Recursive bool
}

// Manager is the privileged filesystem surface. Every method takes a context so
// the caller controls timeout/cancellation. A non-zero exit from a shelled
// command becomes an *exec.CommandError carrying the exit code and stderr.
type Manager interface {
	// ReadFile returns the contents of path. A path that does not exist yields
	// (nil, nil) — absence is not an error, matching the "read whatever is
	// there, empty if nothing" contract callers depend on.
	ReadFile(ctx context.Context, path string) ([]byte, error)
	// ReadDir lists the immediate entries of a directory (no recursion). A path
	// that does not exist yields (nil, nil) — absence is an empty listing, the
	// same "absent is empty" contract as ReadFile — so a caller enumerating a
	// managed config directory that has never been created treats it as empty.
	ReadDir(ctx context.Context, path string) ([]DirEntry, error)
	// WriteFile writes data to path atomically. When the Runner's backend is
	// Direct the write is also symlink-safe (fd-anchored); see the package doc.
	WriteFile(ctx context.Context, path string, data []byte, opts WriteOptions) error
	// Exists reports whether path exists. The probe runs through the privilege
	// backend so it can see paths in directories the caller cannot traverse
	// (e.g. /etc/sudoers.d, mode 0750). A runner/ctx failure is returned as an
	// error (fail-closed) rather than reported as "absent".
	Exists(ctx context.Context, path string) (bool, error)
	// Mkdir creates a directory per opts.
	Mkdir(ctx context.Context, path string, opts MkdirOptions) error
	// Remove deletes a single file and returns any error.
	Remove(ctx context.Context, path string) error
	// RemoveDir removes a directory and its contents. It refuses any target at
	// or under a security-relevant system prefix (deny-by-default) and, on the
	// Direct backend, never follows a symlink (fd-anchored recursive delete).
	RemoveDir(ctx context.Context, path string) error
	// Copy copies src to dst and applies opts (mode/ownership) to dst.
	Copy(ctx context.Context, src, dst string, opts WriteOptions) error
	// SetMode sets the file mode (chmod).
	SetMode(ctx context.Context, path string, mode os.FileMode) error
	// SetOwnership sets the file owner and group (chown). Either may be empty;
	// both empty is a no-op.
	SetOwnership(ctx context.Context, path, owner, group string) error
	// SetOwnershipRecursive changes ownership of a path and all its contents
	// (chown -R). Both owner and group empty is a no-op.
	SetOwnershipRecursive(ctx context.Context, path, owner, group string) error
	// IsReadOnly reports whether the filesystem mounted at path is read-only.
	IsReadOnly(ctx context.Context, path string) (bool, error)
	// RemountRW remounts the filesystem at path read-write.
	RemountRW(ctx context.Context, path string) error
}

// manager is the single Manager implementation; the privilege strategy is the
// Runner's, so there is no per-backend type.
type manager struct {
	r pmexec.Runner
}

// New builds a filesystem Manager driven by runner. A nil runner is rejected
// (fail-closed). New is pure — it does not probe the host.
func New(runner pmexec.Runner) (Manager, error) {
	if runner == nil {
		return nil, fmt.Errorf("fs: %w", pmexec.ErrRunnerRequired)
	}
	return &manager{r: runner}, nil
}

// direct reports whether the Runner runs as root with no escalation wrapper, in
// which case the fd-anchored, symlink-safe code paths apply.
func (m *manager) direct() bool { return m.r.Backend() == pmexec.Direct }

// runPriv runs an escalated command through the Runner. A non-zero exit is in
// Result.ExitCode (not the error); the error is non-nil only when the command
// could not be executed or escalation failed.
//
// The Runner forces the C locale so any stderr/stdout the caller parses is the
// stable English form regardless of host locale — ReadFile's "No such file"
// missing-file detection depends on it (a localized cat error would otherwise be
// misread as a hard failure).
func (m *manager) runPriv(ctx context.Context, name string, args ...string) (pmexec.Result, error) {
	return m.r.Run(ctx, pmexec.Command{Name: name, Args: args, Escalate: true})
}

// runPrivStdin is runPriv with stdin (the tee write path).
func (m *manager) runPrivStdin(ctx context.Context, stdin string, name string, args ...string) (pmexec.Result, error) {
	var in *strings.Reader
	if stdin != "" {
		in = strings.NewReader(stdin)
	}
	cmd := pmexec.Command{Name: name, Args: args, Escalate: true}
	if in != nil {
		cmd.Stdin = in
	}
	return m.r.Run(ctx, cmd)
}

// runQuery runs an unprivileged read (findmnt) through the Runner. The Runner
// forces the C locale, keeping the output parse locale-stable.
func (m *manager) runQuery(ctx context.Context, name string, args ...string) (pmexec.Result, error) {
	return m.r.Run(ctx, pmexec.Command{Name: name, Args: args})
}

// cmdError turns a completed command's Result into a typed error when its exit
// code is non-zero; a clean exit returns nil.
func cmdError(name string, res pmexec.Result) error {
	if res.ExitCode == 0 {
		return nil
	}
	return &pmexec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
}

// validateMode rejects a requested file mode that would set the setuid or
// setgid bit. Creating a setuid/setgid file through a privileged op is a
// local-root privilege-escalation primitive (a setuid-root helper, or a
// setgid binary that inherits a privileged group), so every mutation that
// applies a mode (WriteFile, SetMode, Copy) refuses it before any command or
// privileged side effect. The sticky bit and ordinary permission bits remain
// allowed — only the privilege-conferring bits are refused.
func validateMode(m os.FileMode) error {
	if m&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return fmt.Errorf("%w: mode %s requests setuid/setgid", ErrUnsafeMode, modeArg(m))
	}
	return nil
}

// modeArg formats an os.FileMode as the octal string chmod expects, including
// the setuid/setgid/sticky bits (whose Go bit positions differ from unix).
func modeArg(m os.FileMode) string {
	o := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		o |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		o |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		o |= 0o1000
	}
	return fmt.Sprintf("%04o", o)
}

// ValidatePath rejects paths that would be unsafe to pass through a privileged
// command as positional arguments. The checks are intentionally minimal — no
// symlink resolution, no allowlisting of roots — so callers that need stricter
// semantics can layer them on top.
//
//   - empty → ErrInvalidPath (an empty argv entry collapses verb + path and
//     accidentally runs the command against the cwd)
//   - NUL byte → ErrInvalidPath (the system call interprets NUL as string
//     termination; a NUL inside the path lets an attacker smuggle a different
//     path past higher-level filters)
//   - leading `-` → ErrInvalidPath (would be parsed as a flag by rm, chmod,
//     chown, mkdir, etc. — even with a `--` end-of-options separator some tools
//     still treat it as an option in edge versions)
//
// This is the central chokepoint every privileged file op calls before exec.
func ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("%w: path is empty", ErrInvalidPath)
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%w: path contains NUL byte", ErrInvalidPath)
	}
	if strings.HasPrefix(path, "-") {
		return fmt.Errorf("%w: path %q begins with '-' (would be interpreted as an option flag)", ErrInvalidPath, path)
	}
	return nil
}

// Ownership constructs an "owner:group" string for chown commands. If only
// owner is provided, returns "owner". If only group is provided, returns
// ":group". If both are provided, returns "owner:group". Returns empty string
// if both are empty.
func Ownership(owner, group string) string {
	if owner == "" && group == "" {
		return ""
	}
	if group == "" {
		return owner
	}
	if owner == "" {
		return ":" + group
	}
	return owner + ":" + group
}
