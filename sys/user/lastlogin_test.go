package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// Contract (gap #3): LastLogin(ctx, name) returns the most recent login time for
// the named user.
//
//   - It MUST validate the username (same grammar as every other op) BEFORE the
//     Runner ever runs, so a flag-shaped/metacharacter name cannot reach `last`'s
//     argv.
//   - It MUST shell `last -1 -F <name>` (the Runner forces the C locale, so the
//     parser sees the stable English `Mon Jan _2 15:04:05 2006` timestamp).
//   - A user that has NEVER logged in (no record / "wtmp begins" line / empty
//     output) returns the zero time.Time and a NIL error — never logging in is
//     not a failure.
//   - A genuine runner failure (binary missing, context cancelled) propagates.

// TestLastLogin_ParsesTimestamp pins the happy path: a real `last -1 -F` line is
// parsed to the exact login instant.
func TestLastLogin_ParsesTimestamp(t *testing.T) {
	f := exectest.New(exec.Direct)
	// `last -1 -F deploy` under the C locale: the full timestamp is the 4th-…-8th
	// fields ("Mon Jun 16 14:23:01 2025"); the rest is the logout/duration trailer.
	f.Push(exec.Result{Stdout: "deploy   pts/0        192.168.1.10     Mon Jun 16 14:23:01 2025 - Mon Jun 16 16:01:55 2025  (01:38)\n\nwtmp begins Mon Jun  2 09:14:00 2025\n"}, nil)

	got, err := mgr(t, f).LastLogin(context.Background(), "deploy")
	if err != nil {
		t.Fatalf("LastLogin err = %v, want nil", err)
	}
	// `last` prints in host-local time with no zone name, so the parsed instant is
	// the wall-clock time interpreted in the local location. Build the expectation
	// the same way so the assertion holds on any test host's timezone.
	want := time.Date(2025, time.June, 16, 14, 23, 1, 0, time.Local)
	if !got.Equal(want) {
		t.Fatalf("LastLogin = %v, want %v", got, want)
	}

	// argv + escalation: a read, unescalated, with the exact `-1 -F <name>` form.
	calls := f.Calls()
	if len(calls) != 1 {
		t.Fatalf("got %d commands, want 1: %+v", len(calls), calls)
	}
	c := calls[0]
	if c.Name != "last" {
		t.Errorf("command = %q, want last", c.Name)
	}
	if want := []string{"-1", "-F", "deploy"}; !equalArgs(c.Args, want) {
		t.Errorf("argv = %v, want %v", c.Args, want)
	}
}

// TestLastLogin_NeverLoggedIn covers the three "no record" shapes `last` can emit
// for an account that has never authenticated. Each MUST be the zero time with a
// nil error — the rotation policy that consumes this distinguishes "never" from
// "errored", and an error here would wrongly block rotation.
func TestLastLogin_NeverLoggedIn(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
	}{
		// `last` prints the "wtmp begins" footer and nothing else for a user with
		// no login record.
		{"only wtmp-begins footer", "\nwtmp begins Mon Jun  2 09:14:00 2025\n"},
		// Some `last` builds emit a bare "<user> ... no login" / empty body.
		{"empty output", ""},
		{"blank lines only", "\n\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := exectest.New(exec.Direct)
			f.Push(exec.Result{Stdout: tc.stdout}, nil)
			got, err := mgr(t, f).LastLogin(context.Background(), "deploy")
			if err != nil {
				t.Fatalf("never-logged-in must NOT error, got %v", err)
			}
			if !got.IsZero() {
				t.Fatalf("never-logged-in must be the zero time, got %v", got)
			}
		})
	}
}

// TestLastLogin_RejectsInvalidUsername proves validation happens BEFORE the
// Runner: an adversarial name is refused and `last` is never run, so the name can
// never reach argv as a flag or carry a metacharacter.
func TestLastLogin_RejectsInvalidUsername(t *testing.T) {
	// "wrong" derived from the username grammar (lowercase-leading [a-z0-9_-], ≤32)
	// — NOT from `last`'s parser. Each would, unguarded, become a `last` flag or
	// inject a separator.
	bad := []string{
		"",             // empty
		"-F",           // flag-shaped: would be read as a `last` option
		"--help",       // flag-shaped
		"de ploy",      // space: splits into extra argv words
		"deploy\nroot", // newline: control char
		"Deploy",       // uppercase start
		"1deploy",      // digit start
		"root;id",      // metacharacter
	}
	for _, name := range bad {
		f := exectest.New(exec.Direct)
		_, err := mgr(t, f).LastLogin(context.Background(), name)
		if err == nil {
			t.Errorf("LastLogin(%q) err = nil, want a validation rejection", name)
		}
		if n := len(f.Calls()); n != 0 {
			t.Errorf("LastLogin(%q) ran %d commands, want 0 (rejected before the Runner)", name, n)
		}
	}
}

// TestLastLogin_RunnerErrorPropagates proves a genuine execution failure (the
// `last` binary missing, a cancelled context) is surfaced, NOT swallowed as
// "never logged in". Confusing an exec failure for "never" would silently feed a
// wrong answer to the rotation policy.
func TestLastLogin_RunnerErrorPropagates(t *testing.T) {
	t.Run("runner error", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{}, errors.New("exec: \"last\": executable file not found in $PATH"))
		if _, err := mgr(t, f).LastLogin(context.Background(), "deploy"); err == nil {
			t.Fatal("a runner failure must propagate, got nil")
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		f := exectest.New(exec.Direct)
		if _, err := mgr(t, f).LastLogin(ctx, "deploy"); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

func equalArgs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
