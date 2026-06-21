package fs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// names renders entries as "name(d|f)" sorted, so assertions are order-stable
// (os.ReadDir sorts; find does not guarantee order).
func names(entries []DirEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		kind := "f"
		if e.IsDir {
			kind = "d"
		}
		out[i] = e.Name + "(" + kind + ")"
	}
	sort.Strings(out)
	return out
}

// --- ReadDir (escalated / find path) --------------------------------------

func TestReadDir_Sudo_ParsesFindOutput(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	// `%y/%f` per line: a single type char, '/', then the basename (a basename
	// never contains '/', so the first '/' is an unambiguous separator).
	f.Push(pmexec.Result{Stdout: "f/foo.sources\nd/sub\nl/legacy.list\n"}, nil)
	m := mustManager(t, f)

	got, err := m.ReadDir(context.Background(), "/etc/apt/sources.list.d")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"foo.sources(f)", "legacy.list(f)", "sub(d)"}
	if strings.Join(names(got), ",") != strings.Join(want, ",") {
		t.Errorf("entries = %v, want %v", names(got), want)
	}
	// A symlink reports type 'l' from find's %y → classified as not-a-dir, so a
	// caller iterating files (e.g. apt conflict cleanup) processes it. The target
	// carries a trailing slash so find reports ENOTDIR on a non-directory rather
	// than exiting 0 with no output.
	if got := argv(f.Calls()[0]); got != `find /etc/apt/sources.list.d/ -maxdepth 1 -mindepth 1 -printf %y/%f\n` {
		t.Errorf("argv = %q", got)
	}
	if !f.Calls()[0].Escalate {
		t.Error("ReadDir must escalate so it can list dirs the caller cannot traverse")
	}
}

func TestReadDir_Sudo_EmptyDir(t *testing.T) {
	f := exectest.New(pmexec.Sudo) // unscripted → exit 0, empty stdout
	got, err := mustManager(t, f).ReadDir(context.Background(), "/empty")
	if err != nil || len(got) != 0 {
		t.Fatalf("ReadDir(empty) = (%v, %v), want (empty, nil)", got, err)
	}
}

func TestReadDir_Sudo_MissingDirIsErrNotExist(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{ExitCode: 1, Stderr: "find: '/x': No such file or directory"}, nil)
	got, err := mustManager(t, f).ReadDir(context.Background(), "/x")
	// Explicit-absence contract: a missing dir is a wrapped os.ErrNotExist, not a
	// silent empty listing.
	if !errors.Is(err, os.ErrNotExist) || got != nil {
		t.Fatalf("ReadDir(missing) = (%v, %v), want (nil, ErrNotExist)", got, err)
	}
}

func TestReadDir_Sudo_OtherErrorIsCommandError(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{ExitCode: 1, Stderr: "find: '/etc/secret': Permission denied"}, nil)
	if _, err := mustManager(t, f).ReadDir(context.Background(), "/etc/secret"); !errors.As(err, new(*pmexec.CommandError)) {
		t.Fatalf("err = %v, want *exec.CommandError for a non-absent find failure", err)
	}
}

func TestReadDir_Sudo_RunnerErrorPropagates(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{}, pmexec.ErrEscalationUnavailable)
	if _, err := mustManager(t, f).ReadDir(context.Background(), "/x"); !errors.Is(err, pmexec.ErrEscalationUnavailable) {
		t.Fatalf("err = %v, want ErrEscalationUnavailable", err)
	}
}

// A regular file (not a directory): `find /path/` reports ENOTDIR. It must
// surface as an error mirroring the Direct path — never a silent empty listing,
// and NOT the absence sentinel (the file exists, it just isn't a directory).
func TestReadDir_Sudo_NotADirIsError(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{ExitCode: 1, Stderr: "find: '/etc/hostname/': Not a directory"}, nil)
	got, err := mustManager(t, f).ReadDir(context.Background(), "/etc/hostname")
	if err == nil || got != nil {
		t.Fatalf("ReadDir(regular file) = (%v, %v), want (nil, error)", got, err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want a non-directory command error, not the absence sentinel", err)
	}
	if !errors.As(err, new(*pmexec.CommandError)) {
		t.Fatalf("err = %v, want *exec.CommandError", err)
	}
}

// The escalated find target carries a trailing slash so `find` reports ENOTDIR
// on a non-directory (a bare `find /file` exits 0 with no output, which would
// read as a silently-empty directory). Pin that the slash reaches the argv.
func TestReadDir_Sudo_FindTargetsDirectoryWithTrailingSlash(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	f.Push(pmexec.Result{Stdout: "f/a.conf\n"}, nil)
	if _, err := mustManager(t, f).ReadDir(context.Background(), "/etc/app"); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 1 || calls[0].Name != "find" {
		t.Fatalf("calls = %+v, want a single find", calls)
	}
	if len(calls[0].Args) == 0 || calls[0].Args[0] != "/etc/app/" {
		t.Fatalf("find target = %q, want \"/etc/app/\" (trailing slash enforces directory-only semantics)", calls[0].Args)
	}
}

func TestReadDir_Sudo_InvalidPathRejectedBeforeExec(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	if _, err := mustManager(t, f).ReadDir(context.Background(), "-rf"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("err = %v, want ErrInvalidPath", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Errorf("a flag-shaped path reached find (%d calls)", n)
	}
}

func TestReadDir_Sudo_SkipsMalformedAndBlankLines(t *testing.T) {
	f := exectest.New(pmexec.Sudo)
	// A blank line (defensive) and a line with no '/' are skipped, not panicked on.
	f.Push(pmexec.Result{Stdout: "f/ok.sources\n\nbogusnoslash\nd/d1\n"}, nil)
	got, err := mustManager(t, f).ReadDir(context.Background(), "/d")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"d1(d)", "ok.sources(f)"}
	if strings.Join(names(got), ",") != strings.Join(want, ",") {
		t.Errorf("entries = %v, want %v (malformed/blank lines skipped)", names(got), want)
	}
}

// --- ReadDir (Direct / os.ReadDir path) -----------------------------------

func TestReadDir_Direct_ListsRealDir(t *testing.T) {
	m := directManager(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.repo"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := m.ReadDir(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.repo(f)", "child(d)"}
	if strings.Join(names(got), ",") != strings.Join(want, ",") {
		t.Errorf("entries = %v, want %v", names(got), want)
	}
}

func TestReadDir_Direct_MissingDirIsErrNotExist(t *testing.T) {
	m := directManager(t)
	got, err := m.ReadDir(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"))
	// Explicit-absence contract: missing dir → wrapped os.ErrNotExist.
	if !errors.Is(err, os.ErrNotExist) || got != nil {
		t.Fatalf("ReadDir(missing) = (%v, %v), want (nil, ErrNotExist)", got, err)
	}
}

func TestReadDir_Direct_NotADirIsError(t *testing.T) {
	m := directManager(t)
	file := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Reading a regular file as a directory is a real error (ENOTDIR), not "absent".
	if _, err := m.ReadDir(context.Background(), file); err == nil {
		t.Fatal("ReadDir(regular file) err = nil, want a non-directory error")
	}
}

func TestReadDir_Direct_InvalidPathRejected(t *testing.T) {
	m := directManager(t)
	if _, err := m.ReadDir(context.Background(), "-rf"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("err = %v, want ErrInvalidPath", err)
	}
}
