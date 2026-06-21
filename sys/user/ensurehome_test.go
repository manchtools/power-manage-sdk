package user

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// passwdLine is the getent passwd reply Get parses for HomeDir.
const deployPasswd = "deploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\n"

// A missing home is created, seeded from skel, owned recursively by the user,
// and chmod'd to the home-root mode — the full repair.
func TestEnsureHome_MissingCreatesSeedsOwnsAndModes(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: deployPasswd}, nil) // Get: getent passwd
	ffs := newFakeFS().install(t)
	ffs.present["/etc/skel"] = true // skel exists; home does NOT

	if err := mgr(t, f).EnsureHome(context.Background(), "deploy", EnsureHomeOptions{Group: "deploy"}); err != nil {
		t.Fatal(err)
	}
	if len(ffs.mkdirs) != 1 || ffs.mkdirs[0] != "/home/deploy" {
		t.Errorf("mkdirs = %v, want [/home/deploy]", ffs.mkdirs)
	}
	if len(ffs.copies) != 1 || ffs.copies[0].src != "/etc/skel" || ffs.copies[0].dst != "/home/deploy" {
		t.Errorf("copies = %v, want one /etc/skel → /home/deploy", ffs.copies)
	}
	if !ffs.chown.called || ffs.chown.path != "/home/deploy" || ffs.chown.owner != "deploy" || ffs.chown.group != "deploy" {
		t.Errorf("chown = %+v, want recursive deploy:deploy on /home/deploy", ffs.chown)
	}
	if ffs.chmods.path != "/home/deploy" || ffs.chmods.mode != 0o700 {
		t.Errorf("chmod = %+v, want 0700 on the home root", ffs.chmods)
	}
}

// An EXISTING home must NOT be re-seeded from skel (that would clobber the
// user's customised dotfiles) — but ownership and mode are still re-asserted.
func TestEnsureHome_ExistingDoesNotReseedButFixesOwnerAndMode(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: deployPasswd}, nil)
	ffs := newFakeFS().install(t)
	ffs.present["/home/deploy"] = true // home already exists
	ffs.present["/etc/skel"] = true

	if err := mgr(t, f).EnsureHome(context.Background(), "deploy", EnsureHomeOptions{Group: "staff", Mode: 0o711}); err != nil {
		t.Fatal(err)
	}
	if len(ffs.mkdirs) != 0 {
		t.Errorf("mkdirs = %v, want none (home already exists)", ffs.mkdirs)
	}
	if len(ffs.copies) != 0 {
		t.Errorf("copies = %v, want NO skel reseed over an existing home", ffs.copies)
	}
	if !ffs.chown.called || ffs.chown.group != "staff" {
		t.Errorf("chown = %+v, want recursive ownership with group staff", ffs.chown)
	}
	if ffs.chmods.mode != 0o711 {
		t.Errorf("chmod mode = %v, want the requested 0711", ffs.chmods.mode)
	}
}

// With no explicit Group, ownership resolves to the user's actual primary group
// (id -gn), not a hardcoded assumption.
func TestEnsureHome_DefaultsGroupToPrimary(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: deployPasswd}, nil)                       // Get: getent passwd
	f.Push(exec.Result{Stdout: "deploy:x:1001:\n"}, nil)                 // Get: getent group 1001
	f.Push(exec.Result{Stdout: "deploy\n"}, nil)                         // Get: id -Gn
	f.Push(exec.Result{Stdout: "deploy:$6$h:19000:0:99999:7:::\n"}, nil) // Get: getent shadow (escalated)
	f.Push(exec.Result{Stdout: "devs\n"}, nil)                           // PrimaryGroup: id -gn
	ffs := newFakeFS().install(t)
	ffs.present["/home/deploy"] = true

	if err := mgr(t, f).EnsureHome(context.Background(), "deploy", EnsureHomeOptions{}); err != nil {
		t.Fatal(err)
	}
	if ffs.chown.group != "devs" {
		t.Errorf("chown group = %q, want the resolved primary group 'devs'", ffs.chown.group)
	}
}

// Skel absent: the home is still created (empty), no copy attempted.
func TestEnsureHome_NoSkelStillCreatesEmptyHome(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: deployPasswd}, nil)
	ffs := newFakeFS().install(t) // neither home nor skel present

	if err := mgr(t, f).EnsureHome(context.Background(), "deploy", EnsureHomeOptions{Group: "deploy"}); err != nil {
		t.Fatal(err)
	}
	if len(ffs.mkdirs) != 1 {
		t.Errorf("mkdirs = %v, want the home created even without skel", ffs.mkdirs)
	}
	if len(ffs.copies) != 0 {
		t.Errorf("copies = %v, want no copy when skel is absent", ffs.copies)
	}
}

// A nonexistent account is rejected (Get fails) and the filesystem is untouched.
func TestEnsureHome_UserNotFoundErrors(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 2}, nil) // getent passwd: not found
	ffs := newFakeFS().install(t)

	if err := mgr(t, f).EnsureHome(context.Background(), "ghost", EnsureHomeOptions{}); err == nil {
		t.Fatal("EnsureHome on a nonexistent user must error")
	}
	if len(ffs.mkdirs) != 0 || len(ffs.copies) != 0 || ffs.chown.called {
		t.Error("EnsureHome touched the filesystem for a nonexistent user")
	}
}

// A failed home-directory create aborts EnsureHome with the error wrapped, and
// the seed/own/mode steps never run on a directory that wasn't created.
func TestEnsureHome_MkdirFailureAborts(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: deployPasswd}, nil) // Get: getent passwd
	ffs := newFakeFS().install(t)
	ffs.present["/etc/skel"] = true // home is missing → Mkdir is attempted
	ffs.mkdirErr = errors.New("read-only fs")

	err := mgr(t, f).EnsureHome(context.Background(), "deploy", EnsureHomeOptions{Group: "deploy"})
	if err == nil || !strings.Contains(err.Error(), "create") {
		t.Fatalf("err = %v, want a wrapped create failure", err)
	}
	if len(ffs.copies) != 0 || ffs.chown.called || ffs.chmods.path != "" {
		t.Errorf("EnsureHome seeded/owned/chmod'd after a failed mkdir (copies=%v chown=%v chmod=%q)",
			ffs.copies, ffs.chown.called, ffs.chmods.path)
	}
}

// An invalid username is rejected before any lookup or filesystem op.
func TestEnsureHome_InvalidUsernameRejectedBeforeExec(t *testing.T) {
	f := exectest.New(exec.Direct)
	newFakeFS().install(t)
	if err := mgr(t, f).EnsureHome(context.Background(), "-rf", EnsureHomeOptions{}); err == nil {
		t.Fatal("a flag-shaped username must be rejected")
	}
	if len(f.Calls()) != 0 {
		t.Errorf("a flag-shaped username reached exec (%d calls)", len(f.Calls()))
	}
}
