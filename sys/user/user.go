package user

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
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
	// GroupsKnown reports whether Groups is authoritative. If the `id -Gn`
	// supplementary-group lookup failed, Groups is left empty and GroupsKnown is
	// false — so a caller can tell "no supplementary groups" (empty, GroupsKnown=
	// true) apart from "could not determine" (empty, GroupsKnown=false) instead of
	// silently treating a failed lookup as "no groups".
	GroupsKnown bool
	Locked      bool
	// LockedKnown reports whether Locked is authoritative. The locked state lives
	// in the root-only shadow file; if reading it failed or escalation was not
	// authorized, Locked is left false and LockedKnown is false — so a caller can
	// tell "not locked" (Locked=false, LockedKnown=true) apart from "unknown"
	// (Locked=false, LockedKnown=false) and not treat unknown as unlocked.
	LockedKnown bool
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

// EnsureHomeOptions configures EnsureHome.
type EnsureHomeOptions struct {
	// Group owns the home tree (recursively). "" resolves to the user's actual
	// primary group.
	Group string
	// Skel is the skeleton directory copied into a FRESHLY-created home. ""
	// uses /etc/skel. Ignored when the home already exists — existing content is
	// never clobbered.
	Skel string
	// Mode is the home directory's mode. Zero means 0700.
	Mode os.FileMode
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
	EnsureHome(ctx context.Context, name string, opts EnsureHomeOptions) error
	Modify(ctx context.Context, name string, opts ModifyOptions) error
	Delete(ctx context.Context, name string, opts DeleteOptions) error
	Lock(ctx context.Context, name string) error
	Unlock(ctx context.Context, name string) error
	SetPassword(ctx context.Context, name string, password exec.Secret) error
	ExpirePassword(ctx context.Context, name string) error
	PrimaryGroup(ctx context.Context, name string) (string, error)
	SupplementaryGroups(ctx context.Context, name string) ([]string, error)
	KillSessions(ctx context.Context, name string) error
	LastLogin(ctx context.Context, name string) (time.Time, error)
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
	r   exec.Runner
	fsm fsManager
}

// New returns a Manager for the named backend, driven by runner. It is pure:
// it validates the backend is known and does not probe the host. The zero value
// and any unimplemented backend are rejected with ErrUnknownBackend.
func New(b Backend, runner exec.Runner, _ ...Option) (Manager, error) {
	if b != ShadowUtils {
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
	if runner == nil {
		return nil, fmt.Errorf("user: %w", exec.ErrRunnerRequired)
	}
	fsm, err := newFS(runner)
	if err != nil {
		return nil, err
	}
	return &shadowUtils{r: runner, fsm: fsm}, nil
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
	if opts.UID < 0 {
		return fmt.Errorf("invalid UID %d: must be >= 0 (0 = auto-assign)", opts.UID)
	}
	if err := validateAccountFields(opts.Comment, opts.HomeDir, opts.Shell, opts.PrimaryGroup, opts.Groups); err != nil {
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
		if err := u.fsm.SetOwnershipRecursive(ctx, homeDir, name, group); err != nil {
			return fmt.Errorf("fix ownership of existing home %q: %w", homeDir, err)
		}
	}
	return nil
}

// EnsureHome idempotently ensures the existing user `name` has a correctly set
// up home directory: it exists, is seeded from skel when freshly created, is
// owned by the user (recursively), and carries the right mode. It is the repair
// counterpart to Create's creation-time home handling (useradd -m) — for an
// account whose home was created with -M, deleted, or left mis-owned.
//
// When the home is MISSING it is created and seeded from the skeleton (so no
// existing user file can be clobbered — there are none). When the home already
// EXISTS, EnsureHome re-asserts ownership and mode only; it does NOT re-copy
// skel, so a user's customised dotfiles are preserved. The user must already
// exist (use Create to make the account).
func (u *shadowUtils) EnsureHome(ctx context.Context, name string, opts EnsureHomeOptions) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	info, err := u.Get(ctx, name)
	if err != nil {
		return fmt.Errorf("ensure home for %q: %w", name, err)
	}
	home := info.HomeDir
	if home == "" {
		return fmt.Errorf("ensure home for %q: account has no home directory", name)
	}

	group := opts.Group
	if group == "" {
		group, err = u.PrimaryGroup(ctx, name)
		if err != nil {
			return fmt.Errorf("ensure home for %q: resolve primary group: %w", name, err)
		}
	}
	mode := opts.Mode
	if mode == 0 {
		mode = 0o700
	}
	skel := opts.Skel
	if skel == "" {
		skel = "/etc/skel"
	}

	exists, err := u.fsm.Exists(ctx, home)
	if err != nil {
		return fmt.Errorf("ensure home for %q: %w", name, err)
	}
	if !exists {
		if err := u.fsm.Mkdir(ctx, home, fs.MkdirOptions{Mode: mode, Recursive: true}); err != nil {
			return fmt.Errorf("ensure home for %q: create %q: %w", name, home, err)
		}
		skelExists, serr := u.fsm.Exists(ctx, skel)
		if serr != nil {
			return fmt.Errorf("ensure home for %q: probe skeleton %q: %w", name, skel, serr)
		}
		if skelExists {
			if err := u.fsm.CopyTree(ctx, skel, home, fs.WriteOptions{}); err != nil {
				return fmt.Errorf("ensure home for %q: seed from skeleton %q: %w", name, skel, err)
			}
		}
	}
	// Re-assert ownership (recursive, to repair a partially mis-owned tree) and
	// the home-root mode every call, so EnsureHome is idempotent and also fixes a
	// home that exists but is wrong.
	if err := u.fsm.SetOwnershipRecursive(ctx, home, name, group); err != nil {
		return fmt.Errorf("ensure home for %q: %w", name, err)
	}
	if err := u.fsm.SetMode(ctx, home, mode); err != nil {
		return fmt.Errorf("ensure home for %q: %w", name, err)
	}
	return nil
}

// Modify changes account attributes. Empty option fields are left unchanged; if
// nothing is set it is a no-op (no usermod run).
func (u *shadowUtils) Modify(ctx context.Context, name string, opts ModifyOptions) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	if err := validateAccountFields(opts.Comment, opts.HomeDir, opts.Shell, opts.PrimaryGroup, nil); err != nil {
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
		info.GroupsKnown = true // id -Gn succeeded; Groups is authoritative
	}

	// The shadow file is root-only: read it escalated. If escalation is not
	// authorized, leave Locked=false rather than guessing.
	if res, err := u.r.Run(ctx, exec.Command{Name: "getent", Args: []string{"shadow", name}, Escalate: true}); err == nil && res.ExitCode == 0 && res.Stdout != "" {
		sf := strings.Split(strings.TrimSpace(res.Stdout), ":")
		if len(sf) >= 2 {
			info.Locked = strings.HasPrefix(sf[1], "!") || strings.HasPrefix(sf[1], "*")
			info.LockedKnown = true // the shadow read succeeded; Locked is authoritative
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

// validateField rejects values that would corrupt /etc/passwd or inject extra
// fields/records when written via useradd/usermod. Every free-form account field
// (Comment/HomeDir/Shell, and group references) must contain no control
// character (NUL, newline, CR, …) and none of the separators in `reject` — ':'
// is the passwd field separator; ',' is the -G group-list separator. An empty
// value is the "unchanged"/"default" sentinel and is allowed.
func validateField(kind, val, reject string) error {
	for _, r := range val {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid %s: must not contain control characters", kind)
		}
		if strings.ContainsRune(reject, r) {
			return fmt.Errorf("invalid %s: must not contain %q", kind, r)
		}
	}
	return nil
}

// validateAccountFields validates the free-form fields shared by Create/Modify.
// reject for a passwd field is ":"; group references also reject ",".
func validateAccountFields(comment, homeDir, shell, primaryGroup string, groups []string) error {
	if err := validateField("comment", comment, ":"); err != nil {
		return err
	}
	if err := validateField("home directory", homeDir, ":"); err != nil {
		return err
	}
	if err := validateHomeDir(homeDir); err != nil {
		return err
	}
	if err := validateField("shell", shell, ":"); err != nil {
		return err
	}
	if err := validateShell(shell); err != nil {
		return err
	}
	if err := validateField("primary group", primaryGroup, ":,"); err != nil {
		return err
	}
	for _, g := range groups {
		if err := validateField("supplementary group", g, ":,"); err != nil {
			return err
		}
	}
	return nil
}

// worldWritablePersistenceRoots are directories any unprivileged user can write
// to (or that are otherwise unsafe to anchor an account in). A home or login
// shell placed DIRECTLY under one of these is an attacker-seedable persistence
// point — a backdoor account whose home or shell an unprivileged process already
// controls — so such paths are refused before useradd/usermod/chown runs.
// Membership is by the path's PARENT being exactly one of these (a home like
// /tmp/deploy), not a prefix match: a legitimately nested path such as a test's
// /tmp/<suite>/<n> temp dir is two levels down and is not anchored here.
var worldWritablePersistenceRoots = map[string]bool{
	"/tmp":     true,
	"/var/tmp": true,
	"/dev/shm": true,
}

// shellMetacharacters are bytes that have no place in an absolute executable
// path and that would be dangerous if the value were ever re-expanded by a
// shell. A login shell is passed to useradd/usermod as an argv argument (no
// shell interpretation), but rejecting these is cheap defense-in-depth and keeps
// the value to a plain pathname.
const shellMetacharacters = " \t$&|;<>()`\\\"'*?!{}[]~#"

// validateHomeDir rejects an unsafe home directory before it reaches
// useradd/usermod (and, for an existing home, before the recursive chown). An
// empty value is the "default"/"unchanged" sentinel and is allowed. The contract:
// a home must be an absolute path, contain no ".." traversal component, and not
// be a sensitive system directory (the filesystem root or a top-level system
// dir) or an attacker-seedable persistence point (a path anchored directly under
// a world-writable directory). Control characters and ':' are already rejected by
// validateField.
func validateHomeDir(homeDir string) error {
	if homeDir == "" {
		return nil
	}
	if !strings.HasPrefix(homeDir, "/") {
		return fmt.Errorf("invalid home directory %q: must be an absolute path", homeDir)
	}
	if hasDotDot(homeDir) {
		return fmt.Errorf("invalid home directory %q: must not contain a %q traversal component", homeDir, "..")
	}
	clean := path.Clean(homeDir)
	// The filesystem root and a bare top-level directory (/, /etc, /usr, …) are
	// never a legitimate per-account home; anchoring a home there would hand the
	// account ownership of a system directory (and a recursive chown over it).
	if clean == "/" || path.Dir(clean) == "/" {
		return fmt.Errorf("invalid home directory %q: must not be the filesystem root or a top-level system directory", homeDir)
	}
	if worldWritablePersistenceRoots[path.Dir(clean)] {
		return fmt.Errorf("invalid home directory %q: must not be anchored directly under a world-writable directory", homeDir)
	}
	return nil
}

// validateShell rejects an unsafe login shell before it reaches useradd/usermod.
// An empty value is the "default" sentinel (Create fills in DefaultShell) and is
// allowed. The contract: a shell must be an absolute path, contain no ".."
// traversal component, no shell metacharacters, and must not live in a
// world-writable directory tree (a /tmp, /var/tmp, /dev/shm executable an
// unprivileged attacker can replace). Control characters and ':' are already
// rejected by validateField.
func validateShell(shell string) error {
	if shell == "" {
		return nil
	}
	if !strings.HasPrefix(shell, "/") {
		return fmt.Errorf("invalid shell %q: must be an absolute path", shell)
	}
	if hasDotDot(shell) {
		return fmt.Errorf("invalid shell %q: must not contain a %q traversal component", shell, "..")
	}
	if strings.ContainsAny(shell, shellMetacharacters) {
		return fmt.Errorf("invalid shell %q: must not contain shell metacharacters", shell)
	}
	clean := path.Clean(shell)
	for root := range worldWritablePersistenceRoots {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return fmt.Errorf("invalid shell %q: must not live in a world-writable directory", shell)
		}
	}
	return nil
}

// hasDotDot reports whether an absolute path contains a ".." path component
// (".."-anywhere, including a trailing or interior one). It splits on '/' so a
// filename that merely contains the bytes ".." (e.g. "/bin/a..b") is not flagged.
func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}
