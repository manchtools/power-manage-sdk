package log

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(Journald, nil); err == nil {
		t.Error("New(_, nil) returned nil error")
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	for _, b := range []Backend{0, Backend(-1), Backend(99)} {
		if _, err := New(b, exectest.New(exec.Direct)); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) err = %v, want ErrUnknownBackend", b, err)
		}
	}
}

func TestNew_Backends(t *testing.T) {
	if s, err := New(Journald, exectest.New(exec.Direct)); err != nil {
		t.Errorf("New(Journald): %v", err)
	} else if _, ok := s.(*journaldSource); !ok {
		t.Errorf("New(Journald) = %T", s)
	}
	if s, err := New(Syslog, exectest.New(exec.Direct)); err != nil {
		t.Errorf("New(Syslog): %v", err)
	} else if _, ok := s.(*syslogSource); !ok {
		t.Errorf("New(Syslog) = %T", s)
	}
}

func TestBackendString(t *testing.T) {
	cases := map[Backend]string{Journald: "journald", Syslog: "syslog", Backend(0): "Backend(0)"}
	for b, want := range cases {
		if got := b.String(); got != want {
			t.Errorf("Backend(%d).String() = %q, want %q", int(b), got, want)
		}
	}
}

func TestCappedLines(t *testing.T) {
	cases := map[int]int{0: defaultLines, -5: defaultLines, 50: 50, 10000: 10000, 20000: maxLines}
	for in, want := range cases {
		if got := cappedLines(in); got != want {
			t.Errorf("cappedLines(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestValidateQuery(t *testing.T) {
	cases := []struct {
		name    string
		q       Query
		wantErr bool
	}{
		{"empty ok", Query{}, false},
		{"valid priority name", Query{Priority: "warning"}, false},
		{"valid priority num", Query{Priority: "3"}, false},
		{"valid grep", Query{Grep: "error|fail"}, false},
		{"bad priority", Query{Priority: "loud"}, true},
		{"grep too long", Query{Grep: string(make([]byte, maxGrepLen+1))}, true},
		{"grep ReDoS", Query{Grep: "(a+)+"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateQuery(tc.q)
			if tc.wantErr && !errors.Is(err, ErrInvalidQuery) {
				t.Errorf("validateQuery(%+v) = %v, want ErrInvalidQuery", tc.q, err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateQuery(%+v) = %v, want nil", tc.q, err)
			}
		})
	}
}

func TestRunEscalated(t *testing.T) {
	ctx := context.Background()
	t.Run("escalates and returns stdout", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{Stdout: "line\n"}, nil)
		out, err := runEscalated(ctx, r, nil, "journalctl", "-n", "1")
		if err != nil || out != "line\n" {
			t.Fatalf("= (%q,%v)", out, err)
		}
		if !r.Calls()[0].Escalate {
			t.Error("log reads must escalate (system logs need root)")
		}
	})
	t.Run("non-zero exit errors", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{ExitCode: 1, Stderr: "boom"}, nil)
		if _, err := runEscalated(ctx, r, nil, "journalctl"); err == nil {
			t.Error("non-zero exit must error")
		}
	})
	t.Run("okExitCodes tolerated", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{ExitCode: 1, Stdout: ""}, nil) // grep "no match"
		if _, err := runEscalated(ctx, r, map[int]bool{1: true}, "grep", "x"); err != nil {
			t.Errorf("exit 1 in okExitCodes must be tolerated, got %v", err)
		}
	})
	t.Run("exec error", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{}, errors.New("gone"))
		if _, err := runEscalated(ctx, r, nil, "journalctl"); err == nil {
			t.Error("exec error must surface")
		}
	})
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name       string
		journalctl bool
		syslog     bool
		want       []Backend
	}{
		{"none", false, false, nil},
		{"journald only", true, false, []Backend{Journald}},
		{"syslog only", false, true, []Backend{Syslog}},
		{"both", true, true, []Backend{Journald, Syslog}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prevLP, prevStat := lookPath, statFile
			t.Cleanup(func() { lookPath, statFile = prevLP, prevStat })
			lookPath = func(string) (string, error) {
				if tc.journalctl {
					return "/usr/bin/journalctl", nil
				}
				return "", errors.New("nope")
			}
			statFile = func(string) (os.FileInfo, error) {
				if tc.syslog {
					return nil, nil
				}
				return nil, errors.New("nope")
			}
			got := Detect(context.Background())
			if len(got) != len(tc.want) {
				t.Fatalf("Detect = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Detect[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
