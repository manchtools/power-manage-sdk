package log

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

func TestSplitLines(t *testing.T) {
	if got := splitLines(""); len(got) != 0 {
		t.Errorf("splitLines(empty) = %v, want []", got)
	}
	if got := splitLines("a\nb\n"); strings.Join(got, ",") != "a,b" {
		t.Errorf("splitLines = %v, want [a b] (trailing newline dropped)", got)
	}
	if got := splitLines("only"); strings.Join(got, ",") != "only" {
		t.Errorf("splitLines(no newline) = %v", got)
	}
}

func TestJournald_QueryArgv(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: "l1\nl2\n"}, nil)
	s, _ := New(Journald, r)
	lines, err := s.Query(context.Background(), Query{
		Unit: "sshd.service", Since: "yesterday", Until: "now",
		Priority: "warning", Grep: "fail", Lines: 250,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, ",") != "l1,l2" {
		t.Errorf("lines = %v", lines)
	}
	argv := strings.Join(r.Calls()[0].Args, " ")
	for _, want := range []string{"--no-pager", "-n 250", "-u sshd.service", "--since yesterday", "--until now", "-p warning", "--grep fail"} {
		if !strings.Contains(argv, want) {
			t.Errorf("journalctl argv missing %q\n  got: %q", want, argv)
		}
	}
	if !r.Calls()[0].Escalate {
		t.Error("journald read must escalate")
	}
}

func TestJournald_QueryDefaultsAndMinimal(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: ""}, nil)
	s, _ := New(Journald, r)
	if _, err := s.Query(context.Background(), Query{}); err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(r.Calls()[0].Args, " ")
	if !strings.Contains(argv, "-n 100") { // default line cap
		t.Errorf("default lines should be 100: %q", argv)
	}
	for _, absent := range []string{"-u ", "--since", "--until", "-p ", "--grep"} {
		if strings.Contains(argv, absent) {
			t.Errorf("minimal query must not emit %q: %q", absent, argv)
		}
	}
}

func TestJournald_QueryValidationRejectsBeforeExec(t *testing.T) {
	r := exectest.New(exec.Direct)
	s, _ := New(Journald, r)
	if _, err := s.Query(context.Background(), Query{Grep: "(a+)+"}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("err = %v, want ErrInvalidQuery", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("an invalid query must run nothing")
	}
}

func TestJournald_QueryRunError(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{ExitCode: 1, Stderr: "boom"}, nil)
	s, _ := New(Journald, r)
	if _, err := s.Query(context.Background(), Query{}); err == nil {
		t.Error("a journalctl failure must surface")
	}
}

// withSyslogFixture points syslogPaths + statFile at a fake existing file.
func withSyslogFixture(t *testing.T, exists bool) {
	t.Helper()
	prevPaths, prevStat := syslogPaths, statFile
	t.Cleanup(func() { syslogPaths, statFile = prevPaths, prevStat })
	syslogPaths = []string{"/var/log/syslog"}
	statFile = func(string) (os.FileInfo, error) {
		if exists {
			return nil, nil
		}
		return nil, errors.New("not found")
	}
}

func TestSyslog_QueryTailAndGrep(t *testing.T) {
	withSyslogFixture(t, true)
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: "alpha error\nbeta ok\ngamma error\n"}, nil)
	s, _ := New(Syslog, r)
	lines, err := s.Query(context.Background(), Query{Lines: 50, Grep: "error"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, ",") != "alpha error,gamma error" {
		t.Errorf("grep-filtered lines = %v, want the two error lines", lines)
	}
	argv := strings.Join(r.Calls()[0].Args, " ")
	if argv != "-n 50 -- /var/log/syslog" || r.Calls()[0].Name != "tail" || !r.Calls()[0].Escalate {
		t.Errorf("tail argv = %q (name=%s escalate=%v)", argv, r.Calls()[0].Name, r.Calls()[0].Escalate)
	}
}

func TestSyslog_QueryNoGrepReturnsAll(t *testing.T) {
	withSyslogFixture(t, true)
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: "a\nb\n"}, nil)
	s, _ := New(Syslog, r)
	lines, err := s.Query(context.Background(), Query{})
	if err != nil || strings.Join(lines, ",") != "a,b" {
		t.Fatalf("= (%v,%v)", lines, err)
	}
}

func TestSyslog_QueryNoFile(t *testing.T) {
	withSyslogFixture(t, false)
	r := exectest.New(exec.Direct)
	s, _ := New(Syslog, r)
	if _, err := s.Query(context.Background(), Query{}); err == nil {
		t.Error("missing syslog file must error")
	}
	if len(r.Calls()) != 0 {
		t.Error("no file → no command")
	}
}

func TestSyslog_QueryRunError(t *testing.T) {
	withSyslogFixture(t, true)
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{ExitCode: 1, Stderr: "permission denied"}, nil)
	s, _ := New(Syslog, r)
	if _, err := s.Query(context.Background(), Query{}); err == nil {
		t.Error("a tail failure must surface")
	}
}

func TestSyslog_QueryValidationRejects(t *testing.T) {
	withSyslogFixture(t, true)
	r := exectest.New(exec.Direct)
	s, _ := New(Syslog, r)
	if _, err := s.Query(context.Background(), Query{Priority: "loud"}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("err = %v, want ErrInvalidQuery", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("invalid query → no command")
	}
}

// A grep pattern that passes the structural guard but is not valid RE2 surfaces
// as ErrInvalidQuery from the syslog compile — and must do so BEFORE any
// escalated tail runs (compile-before-privileged-read).
func TestSyslog_QueryBadRegexCompile(t *testing.T) {
	withSyslogFixture(t, true)
	r := exectest.New(exec.Direct)
	s, _ := New(Syslog, r)
	if _, err := s.Query(context.Background(), Query{Grep: "[unclosed"}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("err = %v, want ErrInvalidQuery for an uncompilable pattern", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("a malformed grep must fail before any escalated tail runs")
	}
}
