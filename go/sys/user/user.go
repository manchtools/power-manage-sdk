package user

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// queryTimeout caps a query op when the caller's context carries no deadline so
// a hung getent/id (e.g. a stalled NSS/LDAP/SSSD backend) cannot pin the call
// indefinitely. Local lookups return in milliseconds; 10s leaves headroom.
const queryTimeout = 10 * time.Second

// Backend selects the user/group implementation. It is passed explicitly even
// though shadow-utils is the only value today; the zero value is invalid
// (New → ErrUnknownBackend) and a real second backend (adduser/homed/busybox)
// is appended when actually written.
type Backend int

// ShadowUtils is the useradd/usermod/userdel/chpasswd/chage implementation.
const ShadowUtils Backend = iota + 1

// ErrUnknownBackend is returned by New for the zero value or any Backend the
// SDK does not implement (fail-closed).
var ErrUnknownBackend = fmt.Errorf("user: unknown backend")

// Info holds the current state of a user account.
type Info struct {
	UID     int
	GID     int
	Comment string
	HomeDir string
	Shell   string
	Groups  []string // supplementary groups (excluding the primary)
	Locked  bool
}

// CreateOptions configures Create. The zero value creates a normal interactive
// account with a login shell and the backend's matching primary group, and NO
// home directory.
type CreateOptions struct {
	UID          int      // 0 = auto-assign
	PrimaryGroup string   // group name or numeric GID; "" = useradd matching-group default
	Groups       []string // supplementary groups
	Shell        string   // "" = DefaultShell(System)
	HomeDir      string   // "" = /home/<name>
	Comment      string   // GECOS
	System       bool     // -r system account; also flips DefaultShell to nologin
	CreateHome   bool     // -m; Create handles the "home already exists" -M/chown dance
}

// ModifyOptions configures Modify. An empty string leaves that attribute
// unchanged; if every field is empty Modify is a no-op (no usermod run).
type ModifyOptions struct {
	Shell        string
	HomeDir      string
	Comment      string
	PrimaryGroup string
}

// DeleteOptions configures Delete.
type DeleteOptions struct {
	RemoveHome bool // userdel -r
}

// GroupCreateOptions configures GroupCreate.
type GroupCreateOptions struct {
	GID    int  // 0 = auto-assign
	System bool // -r system group
}

// Manager is the user/group contract. Today shadow-utils is the only
// implementation; the interface leaves room for adduser/systemd-homed/busybox.
type Manager interface {
	// Accounts
	Get(ctx context.Context, name string) (Info, error)
	Exists(ctx context.Context, name string) (bool, error)
	Create(ctx context.Context, name string, opts CreateOptions) error
	Modify(ctx context.Context, name string, opts ModifyOptions) error
	Delete(ctx context.Context, name string, opts DeleteOptions) error
	Lock(ctx context.Context, name string) error
	Unlock(ctx context.Context, name string) error
	SetPassword(ctx context.Context, name string, password exec.Secret) error
	ExpirePassword(ctx context.Context, name string) error
	PrimaryGroup(ctx context.Context, name string) (string, error)
	SupplementaryGroups(ctx context.Context, name string) ([]string, error)
	KillSessions(ctx context.Context, name string) error
	SetHiddenOnLoginScreen(ctx context.Context, name string, hidden bool) error
	// Groups
	GroupExists(ctx context.Context, name string) (bool, error)
	GroupMembers(ctx context.Context, name string) ([]string, error)
	GroupCreate(ctx context.Context, name string, opts GroupCreateOptions) error
	GroupDelete(ctx context.Context, name string) error
	GroupEnsure(ctx context.Context, name string) error
	AddToGroup(ctx context.Context, name, group string) error
	RemoveFromGroup(ctx context.Context, name, group string) error
}

// shadowUtils is the shadow-utils Manager. Every operation runs through the
// injected exec.Runner (reads unescalated; writes and the shadow read with
// Escalate), so the whole package is unit-testable with exectest.FakeRunner.
type shadowUtils struct {
	r exec.Runner
}

// New returns a Manager for the named backend, driven by runner. It is pure:
// it validates the backend is known and does not probe the host. The zero value
// and any unimplemented backend are rejected with ErrUnknownBackend.
func New(b Backend, runner exec.Runner, _ ...Option) (Manager, error) {
	if b != ShadowUtils {
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
	if runner == nil {
		return nil, fmt.Errorf("user: runner is required")
	}
	return &shadowUtils{r: runner}, nil
}

// Option is the functional-option type for backend-specific knobs. None are
// defined today; it reserves the constructor shape.
type Option func(*shadowUtils)

// ensureCtx applies the package query timeout when the caller's context has no
// deadline of its own.
func ensureCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, queryTimeout)
}

// run executes an escalated mutating command and maps a non-zero exit to a
// *exec.CommandError carrying stderr (the "user already exists" context callers
// need).
func (u *shadowUtils) run(ctx context.Context, name string, args ...string) error {
	res, err := u.r.Run(ctx, exec.Command{Name: name, Args: args, Escalate: true})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return &exec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}

// query executes an unescalated read command and returns trimmed stdout, mapping
// a non-zero exit to a *exec.CommandError.
func (u *shadowUtils) query(ctx context.Context, name string, args ...string) (string, error) {
	res, err := u.r.Run(ctx, exec.Command{Name: name, Args: args})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", &exec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return strings.TrimSpace(res.Stdout), nil
}

// =============================================================================
// Accounts
// =============================================================================

// Create creates a new user account. The default-shell policy and the
// "home already exists" -M/chown dance live here (moved out of the agent).
func (u *shadowUtils) Create(ctx context.Context, name string, opts CreateOptions) error {
	if err := validateUsername(name); err != nil {
		return err
	}

	args := make([]string, 0, 16)
	if opts.UID > 0 {
		args = append(args, "-u", strconv.Itoa(opts.UID))
	}
	if opts.PrimaryGroup != "" {
		args = append(args, "-g", opts.PrimaryGroup)
	}
	if len(opts.Groups) > 0 {
		args = append(args, "-G", strings.Join(opts.Groups, ","))
	}
	if opts.HomeDir != "" {
		args = append(args, "-d", opts.HomeDir)
	}
	shell := opts.Shell
	if shell == "" {
		shell = DefaultShell(opts.System)
	}
	args = append(args, "-s", shell)
	if opts.System {
		args = append(args, "-r")
	}

	homeDir := opts.HomeDir
	if homeDir == "" {
		homeDir = "/home/" + name
	}
	_, statErr := os.Stat(homeDir)
	homeExists := statErr == nil
	// useradd -m fails if the home already exists; use -M and fix ownership
	// afterwards so an explicit CreateHome over a pre-seeded directory is
	// idempotent.
	if opts.CreateHome && !homeExists {
		args = append(args, "-m")
	} else {
		args = append(args, "-M")
	}
	if opts.Comment != "" {
		args = append(args, "-c", opts.Comment)
	}
	args = append(args, name)

	if err := u.run(ctx, "useradd", args...); err != nil {
		return err
	}

	if opts.CreateHome && homeExists {
		group := opts.PrimaryGroup
		if group == "" {
			group = name // useradd's matching-group default
		}
		if _, err := setOwnershipRecursive(ctx, homeDir, name, group); err != nil {
			return fmt.Errorf("fix ownership of existing home %q: %w", homeDir, err)
		}
	}
	return nil
}

// Modify changes account attributes. Empty option fields are left unchanged; if
// nothing is set it is a no-op (no usermod run).
func (u *shadowUtils) Modify(ctx context.Context, name string, opts ModifyOptions) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	args := make([]string, 0, 8)
	if opts.Shell != "" {
		args = append(args, "-s", opts.Shell)
	}
	if opts.HomeDir != "" {
		args = append(args, "-d", opts.HomeDir)
	}
	if opts.Comment != "" {
		args = append(args, "-c", opts.Comment)
	}
	if opts.PrimaryGroup != "" {
		args = append(args, "-g", opts.PrimaryGroup)
	}
	if len(args) == 0 {
		return nil // nothing to change
	}
	args = append(args, name)
	return u.run(ctx, "usermod", args...)
}

// Delete removes a user account (and its home when opts.RemoveHome).
func (u *shadowUtils) Delete(ctx context.Context, name string, opts DeleteOptions) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	if opts.RemoveHome {
		return u.run(ctx, "userdel", "-r", name)
	}
	return u.run(ctx, "userdel", name)
}

// Lock locks an account (usermod -L).
func (u *shadowUtils) Lock(ctx context.Context, name string) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	return u.run(ctx, "usermod", "-L", name)
}

// Unlock unlocks an account (usermod -U).
func (u *shadowUtils) Unlock(ctx context.Context, name string) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	return u.run(ctx, "usermod", "-U", name)
}

// Get retrieves the current state of a user.
func (u *shadowUtils) Get(ctx context.Context, name string) (Info, error) {
	if err := validateUsername(name); err != nil {
		return Info{}, err
	}
	ctx, cancel := ensureCtx(ctx)
	defer cancel()

	out, err := u.query(ctx, "getent", "passwd", name)
	if err != nil {
		return Info{}, fmt.Errorf("lookup passwd entry for %q: %w", name, err)
	}
	fields := strings.Split(out, ":")
	if len(fields) < 7 {
		return Info{}, fmt.Errorf("invalid passwd entry for %q", name)
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return Info{}, fmt.Errorf("invalid UID in passwd entry for %q: %w", name, err)
	}
	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		return Info{}, fmt.Errorf("invalid GID in passwd entry for %q: %w", name, err)
	}
	info := Info{UID: uid, GID: gid, Comment: fields[4], HomeDir: fields[5], Shell: fields[6]}

	// Resolve the primary group name from the GID so we filter it out below.
	var primary string
	if gout, err := u.query(ctx, "getent", "group", strconv.Itoa(gid)); err == nil {
		if idx := strings.IndexByte(gout, ':'); idx > 0 {
			primary = gout[:idx]
		}
	}
	if allGroups, err := u.query(ctx, "id", "-Gn", name); err == nil {
		for _, g := range strings.Fields(allGroups) {
			if g != primary {
				info.Groups = append(info.Groups, g)
			}
		}
	}

	// The shadow file is root-only: read it escalated. If escalation is not
	// authorized, leave Locked=false rather than guessing.
	if res, err := u.r.Run(ctx, exec.Command{Name: "getent", Args: []string{"shadow", name}, Escalate: true}); err == nil && res.ExitCode == 0 && res.Stdout != "" {
		sf := strings.Split(strings.TrimSpace(res.Stdout), ":")
		if len(sf) >= 2 {
			info.Locked = strings.HasPrefix(sf[1], "!") || strings.HasPrefix(sf[1], "*")
		}
	}
	return info, nil
}

// Exists reports whether a user exists.
func (u *shadowUtils) Exists(ctx context.Context, name string) (bool, error) {
	if !IsValidName(name) {
		return false, nil
	}
	ctx, cancel := ensureCtx(ctx)
	defer cancel()
	res, err := u.r.Run(ctx, exec.Command{Name: "id", Args: []string{name}})
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// PrimaryGroup returns the user's primary group name.
func (u *shadowUtils) PrimaryGroup(ctx context.Context, name string) (string, error) {
	if err := validateUsername(name); err != nil {
		return "", err
	}
	ctx, cancel := ensureCtx(ctx)
	defer cancel()
	return u.query(ctx, "id", "-gn", name)
}

// SupplementaryGroups returns the user's supplementary groups (excluding the
// primary).
func (u *shadowUtils) SupplementaryGroups(ctx context.Context, name string) ([]string, error) {
	if err := validateUsername(name); err != nil {
		return nil, err
	}
	ctx, cancel := ensureCtx(ctx)
	defer cancel()
	out, err := u.query(ctx, "id", "-Gn", name)
	if err != nil {
		return nil, err
	}
	groups := strings.Fields(out)
	primary, err := u.query(ctx, "id", "-gn", name)
	if err != nil {
		// Cannot guarantee the primary is excluded (the method's contract), so
		// fail closed rather than return a list that may include it.
		return nil, fmt.Errorf("lookup primary group for %q: %w", name, err)
	}
	supplementary := make([]string, 0, len(groups))
	for _, g := range groups {
		if g != primary {
			supplementary = append(supplementary, g)
		}
	}
	return supplementary, nil
}

// =============================================================================
// Validation (pure helpers)
// =============================================================================

// IsValidName reports whether name is a valid, safe POSIX account name: starts
// with a lowercase letter, contains only [a-z0-9_-], max 32 chars. The leading-
// letter rule means a name can never become a useradd/usermod flag, and the
// charset rejects the newline/colon that would inject an extra chpasswd record.
func IsValidName(name string) bool {
	if len(name) == 0 || len(name) > 32 {
		return false
	}
	if name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, c := range name[1:] {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// DefaultShell returns the SDK's default login shell: an interactive shell for
// normal accounts, nologin for system accounts. (Product concepts like
// "disabled" are the consumer's policy — pass Shell explicitly for those.)
func DefaultShell(system bool) string {
	if system {
		return "/usr/sbin/nologin"
	}
	return "/bin/bash"
}

func validateName(kind, name string) error {
	if !IsValidName(name) {
		return fmt.Errorf("invalid %s %q: must start with a lowercase letter and contain only [a-z0-9_-], max 32 chars", kind, name)
	}
	return nil
}

func validateUsername(name string) error { return validateName("username", name) }
