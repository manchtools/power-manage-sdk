package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

// A Runner execution error (here the real "sudo not installed" sentinel, the
// fail-closed result of NewRunner(Sudo) on a host without sudo) propagates
// unchanged from a mutating op — distinct from a non-zero exit.
func TestRun_PropagatesRunnerError(t *testing.T) {
	f := exectest.New(exec.Sudo)
	f.Push(exec.Result{}, exec.ErrEscalationUnavailable)
	if err := mgr(t, f).Lock(context.Background(), "deploy"); !errors.Is(err, exec.ErrEscalationUnavailable) {
		t.Errorf("Lock err = %v, want ErrEscalationUnavailable", err)
	}
}

// ... and from a query op.
func TestQuery_PropagatesRunnerError(t *testing.T) {
	f := exectest.New(exec.Sudo)
	f.Push(exec.Result{}, exec.ErrEscalationUnavailable)
	if _, err := mgr(t, f).PrimaryGroup(context.Background(), "deploy"); !errors.Is(err, exec.ErrEscalationUnavailable) {
		t.Errorf("PrimaryGroup err = %v, want ErrEscalationUnavailable", err)
	}
}

func TestSetPassword_PropagatesRunnerError(t *testing.T) {
	f := exectest.New(exec.Sudo)
	f.Push(exec.Result{}, exec.ErrEscalationUnavailable)
	pw, _ := exec.NewSecret("TestPass123!")
	if err := mgr(t, f).SetPassword(context.Background(), "deploy", pw); !errors.Is(err, exec.ErrEscalationUnavailable) {
		t.Errorf("SetPassword err = %v, want ErrEscalationUnavailable", err)
	}
}

func TestExists_PropagatesRunnerError(t *testing.T) {
	f := exectest.New(exec.Sudo)
	f.Push(exec.Result{}, exec.ErrEscalationUnavailable)
	if _, err := mgr(t, f).Exists(context.Background(), "deploy"); !errors.Is(err, exec.ErrEscalationUnavailable) {
		t.Errorf("Exists err = %v, want ErrEscalationUnavailable", err)
	}
}

func TestGroupExists_PropagatesRunnerError(t *testing.T) {
	f := exectest.New(exec.Sudo)
	f.Push(exec.Result{}, exec.ErrEscalationUnavailable)
	if _, err := mgr(t, f).GroupExists(context.Background(), "staff"); !errors.Is(err, exec.ErrEscalationUnavailable) {
		t.Errorf("GroupExists err = %v, want ErrEscalationUnavailable", err)
	}
}

// AddToGroup / RemoveFromGroup validate the GROUP name too (a valid user but a
// flag-shaped group must be rejected before the Runner).
func TestGroupMembership_RejectsInvalidGroupName(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).AddToGroup(context.Background(), "deploy", "-G"); err == nil {
		t.Error("AddToGroup accepted a flag-shaped group name")
	}
	if err := mgr(t, f).RemoveFromGroup(context.Background(), "deploy", "-G"); err == nil {
		t.Error("RemoveFromGroup accepted a flag-shaped group name")
	}
	if len(f.Calls()) != 0 {
		t.Errorf("ran a command for an invalid group name: %+v", f.Calls())
	}
}

// A caller-supplied deadline is honored as-is (ensureCtx does not wrap it).
func TestQuery_HonorsCallerDeadline(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "staff\n"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := mgr(t, f).PrimaryGroup(ctx, "deploy"); err != nil {
		t.Fatalf("PrimaryGroup with a deadline ctx: %v", err)
	}
}

// A non-zero exit on a QUERY (e.g. `id` for an unknown user) becomes a typed
// *exec.CommandError carrying the tool's exit code/stderr.
func TestQuery_NonZeroExitIsCommandError(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 1, Stderr: "id: 'ghost': no such user"}, nil)
	_, err := mgr(t, f).PrimaryGroup(context.Background(), "ghost")
	var ce *exec.CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 1 {
		t.Errorf("PrimaryGroup err = %v, want *exec.CommandError exit 1", err)
	}
}

// Get surfaces a passwd-lookup failure (unknown user → getent exits 2).
func TestGet_PasswdLookupFailure(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 2}, nil) // getent passwd: not found
	if _, err := mgr(t, f).Get(context.Background(), "ghost"); err == nil {
		t.Error("Get returned nil error for an unknown user")
	}
}

// GroupMembers treats an unreadable/absent group as "no members", not an error.
func TestGroupMembers_AbsentGroupIsEmpty(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 2}, nil) // getent group: not found
	members, err := mgr(t, f).GroupMembers(context.Background(), "ghosts")
	if err != nil || members != nil {
		t.Errorf("GroupMembers = (%v,%v), want (nil,nil) for an absent group", members, err)
	}
}

// SupplementaryGroups: an `id -Gn` failure is surfaced...
func TestSupplementaryGroups_PrimaryListFailure(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 1, Stderr: "id: 'ghost': no such user"}, nil)
	if _, err := mgr(t, f).SupplementaryGroups(context.Background(), "ghost"); err == nil {
		t.Error("SupplementaryGroups returned nil error when id -Gn failed")
	}
}

// ...and if only the PRIMARY-group lookup fails, it FAILS CLOSED rather than
// returning a list that might include the primary (the method's contract is
// "excluding the primary", which it can no longer guarantee).
func TestSupplementaryGroups_PrimaryLookupFailsClosed(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "staff docker sudo\n"}, nil) // id -Gn ok
	f.Push(exec.Result{ExitCode: 1}, nil)                   // id -gn (primary) fails
	groups, err := mgr(t, f).SupplementaryGroups(context.Background(), "deploy")
	if err == nil {
		t.Errorf("SupplementaryGroups returned (%v,nil); want a fail-closed error when the primary lookup fails", groups)
	}
	if groups != nil {
		t.Errorf("groups = %v, want nil on the fail-closed path", groups)
	}
}

// Create surfaces a failure to fix ownership of a pre-existing home.
func TestCreate_ChownFailureSurfaces(t *testing.T) {
	existing := t.TempDir()
	f := exectest.New(exec.Direct)
	f2 := newFakeFS()
	f2.chownErr = exec.ErrEscalationDenied
	f2.install(t)

	err := mgr(t, f).Create(context.Background(), "deploy", CreateOptions{HomeDir: existing, CreateHome: true})
	if err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Errorf("Create err = %v, want an ownership-fix failure", err)
	}
}

// KillSessions surfaces a pkill execution failure (not a non-zero exit).
func TestKillSessions_PkillExecError(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 1}, nil)                // loginctl non-zero → fall through
	f.Push(exec.Result{}, exec.ErrEscalationUnavailable) // pkill cannot execute
	err := mgr(t, f).KillSessions(context.Background(), "deploy")
	if !errors.Is(err, exec.ErrEscalationUnavailable) {
		t.Errorf("KillSessions err = %v, want the wrapped pkill exec error", err)
	}
}

// Get tolerates an unreadable shadow file — the real case being a non-root agent
// whose `getent shadow` escalation is denied. Locked stays false rather than
// erroring.
func TestGet_ShadowUnreadableLeavesUnlocked(t *testing.T) {
	f := exectest.New(exec.Sudo)
	f.Push(exec.Result{Stdout: "deploy:x:1000:1000:Deploy User:/home/deploy:/bin/bash\n"}, nil) // passwd
	f.Push(exec.Result{Stdout: "deploy:x:1000:\n"}, nil)                                        // group
	f.Push(exec.Result{Stdout: "deploy sudo\n"}, nil)                                           // id -Gn
	f.Push(exec.Result{}, exec.ErrEscalationDenied)                                             // shadow: needs a password
	info, err := mgr(t, f).Get(context.Background(), "deploy")
	if err != nil {
		t.Fatalf("Get should tolerate an unreadable shadow: %v", err)
	}
	if info.Locked {
		t.Error("Locked = true, want false when shadow is unreadable")
	}
}
