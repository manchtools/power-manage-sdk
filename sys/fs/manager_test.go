package fs

import (
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// ownerGroup is the current process's owner/group names, for fd-chown-to-self
// tests that must work without real root.
type ownerGroup struct{ owner, group string }

func osUser() (ownerGroup, error) {
	u, err := user.Current()
	if err != nil {
		return ownerGroup{}, err
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		return ownerGroup{}, err
	}
	return ownerGroup{owner: u.Username, group: g.Name}, nil
}

// mustManager builds a Manager over f, failing the test on error.
func mustManager(t *testing.T, f *exectest.FakeRunner) Manager {
	t.Helper()
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// sudoMgr is the escalated-path Manager (Sudo backend): every privileged op is
// shelled through the Runner, so the FakeRunner records the exact argv.
func sudoMgr(t *testing.T) (*exectest.FakeRunner, Manager) {
	t.Helper()
	f := exectest.New(pmexec.Sudo)
	return f, mustManager(t, f)
}

// directManager is the Direct-backend Manager: WriteFile/RemoveDir take the
// fd-anchored, symlink-safe path and never touch the Runner. Used by the
// TOCTOU/symlink tests, which run against test-user-owned temp dirs so they
// succeed without real root.
func directManager(t *testing.T) Manager {
	t.Helper()
	return mustManager(t, exectest.New(pmexec.Direct))
}

// argv renders a recorded Command as "name arg1 arg2 …".
func argv(c pmexec.Command) string {
	return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " "))
}

// stdinOf reads back the stdin a recorded Command carried (nil → "").
func stdinOf(t *testing.T, c pmexec.Command) string {
	t.Helper()
	if c.Stdin == nil {
		return ""
	}
	b, err := io.ReadAll(c.Stdin)
	if err != nil {
		t.Fatalf("read recorded stdin: %v", err)
	}
	return string(b)
}

func TestNew_NilRunnerRejected(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, pmexec.ErrRunnerRequired) {
		t.Fatalf("New(nil) error = %v, want ErrRunnerRequired", err)
	}
	if _, err := New(exectest.New(pmexec.Sudo)); err != nil {
		t.Fatalf("New(runner) = %v, want nil", err)
	}
}

// --- WriteFile (escalated path) -------------------------------------------

func TestWriteFile_Escalated_HappyWithOwnership(t *testing.T) {
	// /etc is root-owned and not group/other-writable, so escalatedParentSafe
	// admits it and the write proceeds to the (faked) root shell.
	f, m := sudoMgr(t)
	if err := m.WriteFile(context.Background(), "/etc/app.conf", []byte("body\n"),
		WriteOptions{Mode: 0o640, Owner: "root", Group: "staff"}); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 1 {
		t.Fatalf("ran %d commands, want 1 (a single root sh -c); got %v", len(calls), callNames(calls))
	}
	c := calls[0]
	if !c.Escalate {
		t.Error("the escalated write must run escalated")
	}
	// args: -c <script> sh <target> <mode> <owner:group> <backup>
	want := []string{"-c", escalatedWriteScript, "sh", "/etc/app.conf", "0640", "root:staff", ""}
	if c.Name != "sh" || strings.Join(c.Args, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("command = %s %q\nwant   = sh %q", c.Name, c.Args, want)
	}
	if body := stdinOf(t, c); body != "body\n" {
		t.Errorf("stdin = %q, want the file content (read by `cat` in the script)", body)
	}
}

func TestWriteFile_Escalated_DefaultModeNoOwner(t *testing.T) {
	f, m := sudoMgr(t)
	if err := m.WriteFile(context.Background(), "/etc/app.conf", []byte("x"), WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	c := f.Calls()[0]
	if c.Args[4] != "0644" {
		t.Errorf("mode arg = %q, want default 0644", c.Args[4])
	}
	if c.Args[5] != "" {
		t.Errorf("owner arg = %q, want empty (script skips chown)", c.Args[5])
	}
	if c.Args[6] != "" {
		t.Errorf("backup arg = %q, want empty", c.Args[6])
	}
}

func TestWriteFile_Escalated_WithBackupArg(t *testing.T) {
	f, m := sudoMgr(t)
	if err := m.WriteFile(context.Background(), "/etc/app.conf", []byte("new"),
		WriteOptions{Backup: "/etc/app.conf.bak"}); err != nil {
		t.Fatal(err)
	}
	if got := f.Calls()[0].Args[6]; got != "/etc/app.conf.bak" {
		t.Errorf("backup arg = %q, want the backup path (the root script does the copy)", got)
	}
}

func TestWriteFile_Escalated_ScriptFailure(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{ExitCode: 1, Stderr: "mktemp: cannot create"}, nil)
	m := mustManager(t, f)
	err := m.WriteFile(context.Background(), "/etc/app.conf", []byte("x"), WriteOptions{})
	if err == nil || !strings.Contains(err.Error(), "write file") {
		t.Fatalf("err = %v, want a wrapped write-file failure", err)
	}
}

// TestWriteFile_Escalated_RefusesUnsafeParent: a parent directory a non-root user
// could write to (here world-writable and not sticky) is refused BEFORE any
// escalation, so the symlink-plant window never opens. The 0777-non-sticky perms
// are unsafe whether or not the test runs as root.
func TestWriteFile_Escalated_RefusesUnsafeParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	f, m := sudoMgr(t)
	err := m.WriteFile(context.Background(), filepath.Join(dir, "f"), []byte("x"), WriteOptions{})
	if !errors.Is(err, ErrUnsafeParentDir) {
		t.Fatalf("err = %v, want ErrUnsafeParentDir", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("ran %d commands; an unsafe parent must be refused before escalating", n)
	}
}

func TestWriteFile_Escalated_RunnerErrorPropagates(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{}, pmexec.ErrEscalationDenied) // the root shell can't escalate
	m := mustManager(t, f)
	if err := m.WriteFile(context.Background(), "/etc/app.conf", []byte("x"), WriteOptions{}); !errors.Is(err, pmexec.ErrEscalationDenied) {
		t.Fatalf("err = %v, want ErrEscalationDenied", err)
	}
}

func TestWriteFile_RejectsInvalidPathAndBackup(t *testing.T) {
	f, m := sudoMgr(t)
	if err := m.WriteFile(context.Background(), "-rf", []byte("x"), WriteOptions{}); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("WriteFile(bad path) err = %v, want ErrInvalidPath", err)
	}
	if err := m.WriteFile(context.Background(), "/ok", []byte("x"), WriteOptions{Backup: "-evil"}); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("WriteFile(bad backup) err = %v, want ErrInvalidPath", err)
	}
	// Backup == target is rejected (backends would diverge: Direct no-ops, the
	// escalated cp errors "same file").
	if err := m.WriteFile(context.Background(), "/etc/app.conf", []byte("x"), WriteOptions{Backup: "/etc/./app.conf"}); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("WriteFile(self-backup) err = %v, want ErrInvalidPath", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("an invalid path reached the Runner (%d calls)", n)
	}
}

func TestWriteFile_CancelledCtxBeforeAnyWork(t *testing.T) {
	f, m := sudoMgr(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.WriteFile(ctx, "/etc/app.conf", []byte("x"), WriteOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("cancelled WriteFile ran %d commands, want 0", n)
	}
}

// --- ReadFile / Exists -----------------------------------------------------

func TestReadFile_ReturnsStdoutVerbatim(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	// The Runner returns cat's stdout verbatim, trailing newline included, so the
	// bytes round-trip exactly with what WriteFile wrote — no re-add, no strip.
	f.Push(pmexec.Result{Stdout: "line1\nline2\n"}, nil)
	m := mustManager(t, f)
	got, err := m.ReadFile(context.Background(), "/etc/app.conf")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "line1\nline2\n" {
		t.Errorf("ReadFile = %q, want the bytes verbatim", got)
	}
	if got := argv(f.Calls()[0]); got != "cat -- /etc/app.conf" {
		t.Errorf("cat argv = %q", got)
	}
	// Locale stability (the "No such file" check working on non-English hosts) is
	// the Runner's invariant now, pinned by exec.TestRunner_ForcesDeterministicEnv
	// + the fs integration suite running under ja_JP — not a per-Command flag.
}

func TestReadFile_DoesNotReAddNewline(t *testing.T) {
	// ReadFile must return the Runner's stdout untouched — no re-add (the old
	// global path stripped + re-added a newline; the Runner preserves it, so a
	// re-add would double it). Newline normalization is the Runner's job.
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{Stdout: "no-newline"}, nil)
	m := mustManager(t, f)
	got, err := m.ReadFile(context.Background(), "/etc/app.conf")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "no-newline" {
		t.Errorf("ReadFile = %q, want the stdout returned untouched", got)
	}
}

func TestReadFile_MissingIsErrNotExist(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{ExitCode: 1, Stderr: "cat: /x: No such file or directory"}, nil)
	m := mustManager(t, f)
	got, err := m.ReadFile(context.Background(), "/x")
	// Explicit-absence contract: missing → wrapped os.ErrNotExist, not silent empty.
	if !errors.Is(err, os.ErrNotExist) || got != nil {
		t.Fatalf("ReadFile(missing) = (%q, %v), want (nil, ErrNotExist)", got, err)
	}
}

func TestReadFile_EmptyFile(t *testing.T) {
	f := exectest.New(pmexec.Sudo) // unscripted → exit 0, empty stdout
	m := mustManager(t, f)
	got, err := m.ReadFile(context.Background(), "/empty")
	if err != nil || got != nil {
		t.Fatalf("ReadFile(empty) = (%q, %v), want (nil, nil)", got, err)
	}
}

func TestReadFile_OtherErrorIsCommandError(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{ExitCode: 1, Stderr: "cat: /etc/shadow: Permission denied"}, nil)
	m := mustManager(t, f)
	if _, err := m.ReadFile(context.Background(), "/etc/shadow"); !errors.As(err, new(*pmexec.CommandError)) {
		t.Fatalf("err = %v, want *exec.CommandError for a non-absent cat failure", err)
	}
}

func TestReadFile_RunnerErrorPropagatesAndValidatesPath(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{}, pmexec.ErrEscalationUnavailable)
	m := mustManager(t, f)
	if _, err := m.ReadFile(context.Background(), "/x"); !errors.Is(err, pmexec.ErrEscalationUnavailable) {
		t.Errorf("err = %v, want ErrEscalationUnavailable", err)
	}
	if _, err := m.ReadFile(context.Background(), "-rf"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("ReadFile(bad path) err = %v, want ErrInvalidPath", err)
	}
}

func TestExists(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo) // unscripted → exit 0
		ok, err := mustManager(t, f).Exists(context.Background(), "/etc/hosts")
		if err != nil || !ok {
			t.Fatalf("Exists = (%v,%v), want (true,nil)", ok, err)
		}
		if got := argv(f.Calls()[0]); got != "test -e /etc/hosts" {
			t.Errorf("argv = %q", got)
		}
	})
	t.Run("absent", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		ok, err := mustManager(t, f).Exists(context.Background(), "/nope")
		if err != nil || ok {
			t.Fatalf("Exists = (%v,%v), want (false,nil)", ok, err)
		}
	})
	t.Run("runner error fails closed", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{}, pmexec.ErrEscalationDenied)
		if _, err := mustManager(t, f).Exists(context.Background(), "/x"); !errors.Is(err, pmexec.ErrEscalationDenied) {
			t.Fatalf("err = %v, want the runner error, not a silent 'absent'", err)
		}
	})
	t.Run("invalid path", func(t *testing.T) {
		if _, err := mustManager(t, exectest.New(pmexec.Sudo)).Exists(context.Background(), "-rf"); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("err = %v, want ErrInvalidPath", err)
		}
	})
}

// --- SetMode / SetOwnership / SetOwnershipRecursive ------------------------

func TestSetMode(t *testing.T) {
	f, m := sudoMgr(t)
	if err := m.SetMode(context.Background(), "/etc/app.conf", 0o600); err != nil {
		t.Fatal(err)
	}
	if got := argv(f.Calls()[0]); got != "chmod 0600 -- /etc/app.conf" {
		t.Errorf("argv = %q", got)
	}
}

func TestSetMode_NonZeroExitAndValidate(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{ExitCode: 1, Stderr: "chmod: bad"}, nil)
	m := mustManager(t, f)
	if err := m.SetMode(context.Background(), "/etc/app.conf", 0o600); !errors.As(err, new(*pmexec.CommandError)) {
		t.Errorf("err = %v, want *exec.CommandError", err)
	}
	if err := m.SetMode(context.Background(), "-rf", 0o600); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("SetMode(bad path) err = %v, want ErrInvalidPath", err)
	}
}

func TestSetOwnership_NoOpWhenEmpty(t *testing.T) {
	f, m := sudoMgr(t)
	if err := m.SetOwnership(context.Background(), "/x", "", ""); err != nil {
		t.Fatal(err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("SetOwnership(\"\",\"\") ran %d commands, want 0", n)
	}
}

func TestSetOwnership_Applies(t *testing.T) {
	f, m := sudoMgr(t)
	if err := m.SetOwnership(context.Background(), "/etc/app.conf", "root", "wheel"); err != nil {
		t.Fatal(err)
	}
	if got := argv(f.Calls()[0]); got != "chown -- root:wheel /etc/app.conf" {
		t.Errorf("argv = %q", got)
	}
	if err := m.SetOwnership(context.Background(), "-rf", "root", ""); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("SetOwnership(bad path) err = %v, want ErrInvalidPath", err)
	}
}

func TestSetOwnershipRecursive(t *testing.T) {
	f, m := sudoMgr(t)
	if err := m.SetOwnershipRecursive(context.Background(), "/home/x", "", ""); err != nil {
		t.Fatal(err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Fatalf("recursive chown with empty ownership ran %d commands, want 0", n)
	}
	if err := m.SetOwnershipRecursive(context.Background(), "/home/x", "x", "x"); err != nil {
		t.Fatal(err)
	}
	if got := argv(f.Calls()[0]); got != "chown -R -- x:x /home/x" {
		t.Errorf("argv = %q", got)
	}
	if err := m.SetOwnershipRecursive(context.Background(), "-rf", "x", "x"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("err = %v, want ErrInvalidPath", err)
	}
}

// --- Copy ------------------------------------------------------------------

func TestCopy(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		f, m := sudoMgr(t)
		if err := m.Copy(context.Background(), "/a", "/b", WriteOptions{}); err != nil {
			t.Fatal(err)
		}
		calls := f.Calls()
		if len(calls) != 1 || argv(calls[0]) != "cp -- /a /b" {
			t.Fatalf("calls = %v, want a single cp", callNames(calls))
		}
	})
	t.Run("with mode and ownership", func(t *testing.T) {
		f, m := sudoMgr(t)
		if err := m.Copy(context.Background(), "/a", "/b", WriteOptions{Mode: 0o600, Owner: "root", Group: "root"}); err != nil {
			t.Fatal(err)
		}
		if names := callNames(f.Calls()); strings.Join(names, ",") != "cp,chmod,chown" {
			t.Errorf("calls = %v, want cp,chmod,chown", names)
		}
	})
	t.Run("cp failure", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "cp: nope"}, nil)
		if err := mustManager(t, f).Copy(context.Background(), "/a", "/b", WriteOptions{}); err == nil ||
			!strings.Contains(err.Error(), "copy file") {
			t.Errorf("err = %v, want a wrapped cp failure", err)
		}
	})
	t.Run("validates both paths", func(t *testing.T) {
		_, m := sudoMgr(t)
		if err := m.Copy(context.Background(), "-a", "/b", WriteOptions{}); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("Copy(bad src) err = %v", err)
		}
		if err := m.Copy(context.Background(), "/a", "-b", WriteOptions{}); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("Copy(bad dst) err = %v", err)
		}
	})
}

// --- Mkdir / Remove --------------------------------------------------------

func TestMkdir(t *testing.T) {
	t.Run("recursive with mode+owner", func(t *testing.T) {
		f, m := sudoMgr(t)
		if err := m.Mkdir(context.Background(), "/srv/app/data", MkdirOptions{Mode: 0o750, Owner: "app", Group: "app", Recursive: true}); err != nil {
			t.Fatal(err)
		}
		calls := f.Calls()
		if got := argv(calls[0]); got != "mkdir -p -- /srv/app/data" {
			t.Errorf("mkdir argv = %q", got)
		}
		if names := callNames(calls); strings.Join(names, ",") != "mkdir,chmod,chown" {
			t.Errorf("calls = %v, want mkdir,chmod,chown", names)
		}
	})
	t.Run("non-recursive bare", func(t *testing.T) {
		f, m := sudoMgr(t)
		if err := m.Mkdir(context.Background(), "/srv/app", MkdirOptions{}); err != nil {
			t.Fatal(err)
		}
		calls := f.Calls()
		if len(calls) != 1 || argv(calls[0]) != "mkdir -- /srv/app" {
			t.Fatalf("calls = %v, want a single bare mkdir", callNames(calls))
		}
	})
	t.Run("mkdir failure", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "mkdir: exists"}, nil)
		if err := mustManager(t, f).Mkdir(context.Background(), "/srv/app", MkdirOptions{}); !errors.As(err, new(*pmexec.CommandError)) {
			t.Errorf("err = %v, want *exec.CommandError", err)
		}
	})
	t.Run("invalid path", func(t *testing.T) {
		if err := mustManager(t, exectest.New(pmexec.Sudo)).Mkdir(context.Background(), "-rf", MkdirOptions{}); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("err = %v, want ErrInvalidPath", err)
		}
	})
}

func TestRemove(t *testing.T) {
	f, m := sudoMgr(t)
	if err := m.Remove(context.Background(), "/tmp/x"); err != nil {
		t.Fatal(err)
	}
	if got := argv(f.Calls()[0]); got != "rm -f -- /tmp/x" {
		t.Errorf("argv = %q", got)
	}
	if err := m.Remove(context.Background(), "-rf"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("Remove(bad path) err = %v, want ErrInvalidPath", err)
	}
	f2 := exectest.New(pmexec.Sudo)
	f2.Push(pmexec.Result{ExitCode: 1, Stderr: "rm: denied"}, nil)
	if err := mustManager(t, f2).Remove(context.Background(), "/tmp/x"); !errors.As(err, new(*pmexec.CommandError)) {
		t.Errorf("err = %v, want *exec.CommandError", err)
	}
}

// --- RemoveDir (escalated path; the Direct fd path is in remove_dir_test.go) -

func TestRemoveDir_Escalated(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	m := mustManager(t, f)
	if err := m.RemoveDir(context.Background(), "/srv/app/data"); err != nil {
		t.Fatal(err)
	}
	if got := argv(f.Calls()[0]); got != "rm -rf -- /srv/app/data" {
		t.Errorf("argv = %q", got)
	}
}

func TestRemoveDir_Rejections(t *testing.T) {
	_, m := sudoMgr(t)
	if err := m.RemoveDir(context.Background(), "-rf"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("RemoveDir(bad path) err = %v, want ErrInvalidPath", err)
	}
	if err := m.RemoveDir(context.Background(), "relative/dir"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("RemoveDir(relative) err = %v, want an absolute-path rejection", err)
	}
	if err := m.RemoveDir(context.Background(), "/etc/sudoers.d"); err == nil || !strings.Contains(err.Error(), "protected") {
		t.Errorf("RemoveDir(protected) err = %v, want a protected-path refusal", err)
	}
}

func TestRemoveDir_EscalatedNonZeroExit(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{ExitCode: 1, Stderr: "rm: busy"}, nil)
	if err := mustManager(t, f).RemoveDir(context.Background(), "/srv/app"); !errors.As(err, new(*pmexec.CommandError)) {
		t.Errorf("err = %v, want *exec.CommandError", err)
	}
}

// --- IsReadOnly / RemountRW ------------------------------------------------

func TestIsReadOnly(t *testing.T) {
	t.Run("ro", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{Stdout: "ro,relatime\n"}, nil)
		ro, err := mustManager(t, f).IsReadOnly(context.Background(), "/")
		if err != nil || !ro {
			t.Fatalf("IsReadOnly = (%v,%v), want (true,nil)", ro, err)
		}
		if got := argv(f.Calls()[0]); got != "findmnt -n -o OPTIONS --target /" {
			t.Errorf("argv = %q", got)
		}
	})
	t.Run("rw", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{Stdout: "rw,relatime\n"}, nil)
		ro, err := mustManager(t, f).IsReadOnly(context.Background(), "/")
		if err != nil || ro {
			t.Fatalf("IsReadOnly = (%v,%v), want (false,nil)", ro, err)
		}
	})
	t.Run("non-zero exit", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{ExitCode: 1}, nil)
		if _, err := mustManager(t, f).IsReadOnly(context.Background(), "/x"); !errors.As(err, new(*pmexec.CommandError)) {
			t.Errorf("err = %v, want *exec.CommandError", err)
		}
	})
	t.Run("runner error", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{}, errors.New("findmnt missing"))
		if _, err := mustManager(t, f).IsReadOnly(context.Background(), "/x"); err == nil {
			t.Error("want the runner error to propagate")
		}
	})
	t.Run("invalid path rejected before exec", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		if _, err := mustManager(t, f).IsReadOnly(context.Background(), "-rf"); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("err = %v, want ErrInvalidPath", err)
		}
		if n := len(f.Calls()); n != 0 {
			t.Errorf("a flag-shaped path reached findmnt (%d calls)", n)
		}
	})
}

func TestRemountRW(t *testing.T) {
	f, m := sudoMgr(t)
	if err := m.RemountRW(context.Background(), "/"); err != nil {
		t.Fatal(err)
	}
	if got := argv(f.Calls()[0]); got != "mount -o remount,rw -- /" {
		t.Errorf("argv = %q, want mount target after --", got)
	}

	fInvalid := exectest.New(pmexec.Sudo)
	if err := mustManager(t, fInvalid).RemountRW(context.Background(), "-O"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("RemountRW(flag-shaped path) err = %v, want ErrInvalidPath", err)
	}
	if n := len(fInvalid.Calls()); n != 0 {
		t.Errorf("RemountRW(flag-shaped path) ran %d command(s) before validation; want 0", n)
	}

	f2 := exectest.New(pmexec.Sudo)
	f2.Push(pmexec.Result{ExitCode: 1, Stderr: "mount: ro"}, nil)
	if err := mustManager(t, f2).RemountRW(context.Background(), "/"); err == nil ||
		!strings.Contains(err.Error(), "remount") {
		t.Errorf("err = %v, want a wrapped remount failure", err)
	}
}

// --- pure helpers ----------------------------------------------------------

func TestOwnership(t *testing.T) {
	for _, tt := range []struct{ owner, group, want string }{
		{"root", "root", "root:root"},
		{"root", "", "root"},
		{"", "root", ":root"},
		{"", "", ""},
	} {
		if got := Ownership(tt.owner, tt.group); got != tt.want {
			t.Errorf("Ownership(%q,%q) = %q, want %q", tt.owner, tt.group, got, tt.want)
		}
	}
}

func TestModeArg(t *testing.T) {
	for _, tt := range []struct {
		mode os.FileMode
		want string
	}{
		{0o644, "0644"},
		{0o600, "0600"},
		{0o755, "0755"},
		{os.FileMode(0o755) | os.ModeSetuid, "4755"},
		{os.FileMode(0o2755) | os.ModeSetgid, "2755"},
		{os.FileMode(0o1777) | os.ModeSticky, "1777"},
	} {
		if got := modeArg(tt.mode); got != tt.want {
			t.Errorf("modeArg(%v) = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestGetOwnership_SelfAndMissing(t *testing.T) {
	dir := t.TempDir()
	owner, group := GetOwnership(dir)
	// The temp dir is owned by the test user; at minimum the lookups must not
	// crash and should resolve to non-empty names on a normal host.
	if owner == "" && group == "" {
		t.Skip("ownership name lookup unavailable in this environment")
	}
	o, g := GetOwnership("/nonexistent-pm-fs-xyz")
	if o != "" || g != "" {
		t.Errorf("GetOwnership(missing) = (%q,%q), want empties", o, g)
	}
}

// callNames extracts the command names from a recorded call log.
func callNames(calls []pmexec.Command) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.Name
	}
	return out
}

// --- WriteFile (Direct / fd path) error & backup branches -----------------

func TestWriteFile_Direct_WithBackupAndOwnership(t *testing.T) {
	m := directManager(t)
	dir := t.TempDir()
	dest := dir + "/app"
	backup := dir + "/app.bak"
	if err := os.WriteFile(dest, []byte("OLD"), 0o644); err != nil {
		t.Fatalf("seed dest: %v", err)
	}

	u, err := osUser()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	if err := m.WriteFile(context.Background(), dest, []byte("NEW"),
		WriteOptions{Mode: 0o600, Owner: u.owner, Group: u.group, Backup: backup}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "NEW" {
		t.Errorf("dest = %q, want NEW", got)
	}
	if got, _ := os.ReadFile(backup); string(got) != "OLD" {
		t.Errorf("backup = %q, want the prior content OLD", got)
	}
	if info, _ := os.Stat(dest); info.Mode().Perm() != 0o600 {
		t.Errorf("dest mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestWriteFile_Direct_ResolveOwnershipError(t *testing.T) {
	m := directManager(t)
	dest := t.TempDir() + "/f"
	err := m.WriteFile(context.Background(), dest, []byte("x"),
		WriteOptions{Owner: "pm-nonexistent-user-zzz", Group: "pm-nonexistent-group-zzz"})
	if err == nil || !strings.Contains(err.Error(), "resolve owner") {
		t.Fatalf("err = %v, want a resolve-owner failure", err)
	}
}

func TestWriteFile_Direct_SafeReplaceError(t *testing.T) {
	m := directManager(t)
	// Parent directory does not exist → the temp create fails.
	dest := t.TempDir() + "/missing-subdir/f"
	if err := m.WriteFile(context.Background(), dest, []byte("x"), WriteOptions{}); err == nil ||
		!strings.Contains(err.Error(), "write file") {
		t.Fatalf("err = %v, want a wrapped write failure", err)
	}
}

// --- Copy / Mkdir post-create metadata failures ---------------------------

func TestCopy_PostCopyFailures(t *testing.T) {
	t.Run("chmod fails", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{}, nil)                             // cp ok
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "chmod"}, nil) // chmod fails
		if err := mustManager(t, f).Copy(context.Background(), "/a", "/b", WriteOptions{Mode: 0o600}); !errors.As(err, new(*pmexec.CommandError)) {
			t.Errorf("err = %v, want *exec.CommandError from chmod", err)
		}
	})
	t.Run("chown fails", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{}, nil)                             // cp ok
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "chown"}, nil) // chown fails
		if err := mustManager(t, f).Copy(context.Background(), "/a", "/b", WriteOptions{Owner: "root"}); !errors.As(err, new(*pmexec.CommandError)) {
			t.Errorf("err = %v, want *exec.CommandError from chown", err)
		}
	})
}

func TestMkdir_PostMkdirFailures(t *testing.T) {
	t.Run("chmod fails", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{}, nil)                             // mkdir ok
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "chmod"}, nil) // chmod fails
		if err := mustManager(t, f).Mkdir(context.Background(), "/srv/app", MkdirOptions{Mode: 0o750}); !errors.As(err, new(*pmexec.CommandError)) {
			t.Errorf("err = %v, want *exec.CommandError from chmod", err)
		}
	})
	t.Run("chown fails", func(t *testing.T) {
		f := exectest.New(pmexec.Sudo)
		f.Push(pmexec.Result{}, nil)                             // mkdir ok
		f.Push(pmexec.Result{ExitCode: 1, Stderr: "chown"}, nil) // chown fails
		if err := mustManager(t, f).Mkdir(context.Background(), "/srv/app", MkdirOptions{Owner: "app"}); !errors.As(err, new(*pmexec.CommandError)) {
			t.Errorf("err = %v, want *exec.CommandError from chown", err)
		}
	})
}

func TestWriteFile_Direct_BackupWriteError(t *testing.T) {
	m := directManager(t)
	dir := t.TempDir()
	dest := dir + "/app"
	if err := os.WriteFile(dest, []byte("OLD"), 0o644); err != nil {
		t.Fatalf("seed dest: %v", err)
	}
	// Backup target's parent does not exist → the backup copy fails, so the
	// whole write fails (and dest is left intact by safeBackupAndReplace).
	if err := m.WriteFile(context.Background(), dest, []byte("NEW"),
		WriteOptions{Backup: dir + "/missing/app.bak"}); err == nil || !strings.Contains(err.Error(), "write file") {
		t.Fatalf("err = %v, want a wrapped backup-write failure", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "OLD" {
		t.Errorf("dest = %q, want the original OLD preserved on backup failure", got)
	}
}

func TestWriteFile_Direct_FchownError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chown to root succeeds, so the fchown-error branch can't be hit")
	}
	m := directManager(t)
	dest := t.TempDir() + "/f"
	// A non-root process cannot chown a file to root → FchownNoFollow fails.
	if err := m.WriteFile(context.Background(), dest, []byte("x"),
		WriteOptions{Owner: "root", Group: "root"}); err == nil || !strings.Contains(err.Error(), "set ownership") {
		t.Fatalf("err = %v, want a set-ownership failure", err)
	}
}

func TestRunChecked_RunnerErrorPropagates(t *testing.T) {
	// SetMode routes through runChecked; a runner (not exit) error must surface.
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{}, pmexec.ErrEscalationUnavailable)
	if err := mustManager(t, f).SetMode(context.Background(), "/etc/app.conf", 0o644); !errors.Is(err, pmexec.ErrEscalationUnavailable) {
		t.Fatalf("err = %v, want ErrEscalationUnavailable", err)
	}
}
