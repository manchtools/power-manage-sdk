package user

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// noRun asserts the Runner was never invoked — an invalid request must be
// rejected before any useradd/usermod/groupadd runs.
func noRun(t *testing.T, f *exectest.FakeRunner) {
	t.Helper()
	if n := len(f.Calls()); n != 0 {
		t.Errorf("an invalid request reached the Runner (%d calls): %+v", n, f.Calls())
	}
}

func TestCreate_RejectsNegativeUID(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).Create(context.Background(), "deploy", CreateOptions{UID: -1}); err == nil ||
		!strings.Contains(err.Error(), "UID") {
		t.Fatalf("Create(UID=-1) err = %v, want an invalid-UID error", err)
	}
	noRun(t, f)
}

func TestGroupCreate_RejectsNegativeGID(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).GroupCreate(context.Background(), "staff", GroupCreateOptions{GID: -5}); err == nil ||
		!strings.Contains(err.Error(), "GID") {
		t.Fatalf("GroupCreate(GID=-5) err = %v, want an invalid-GID error", err)
	}
	noRun(t, f)
}

// TestCreate_RejectsFieldInjection: free-form account fields written into
// /etc/passwd (or the -G list) must reject control characters and the field
// separators ':' / ',' so a caller cannot corrupt the file or inject extra
// fields/records (GECOS injection, extra supplementary groups).
func TestCreate_RejectsFieldInjection(t *testing.T) {
	cases := map[string]CreateOptions{
		"newline in comment":      {Comment: "Real Name\nroot:x:0:0::/root:/bin/sh"},
		"colon in comment":        {Comment: "a:b"},
		"NUL in home dir":         {HomeDir: "/home/x\x00y"},
		"newline in shell":        {Shell: "/bin/sh\n/bin/evil"},
		"colon in shell":          {Shell: "/bin/sh:x"},
		"comma in primary group":  {PrimaryGroup: "wheel,root"},
		"colon in supplementary":  {Groups: []string{"ok", "bad:grp"}},
		"comma in supplementary":  {Groups: []string{"a,b"}},
		"control char in comment": {Comment: "tab\there"},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			f := exectest.New(exec.Direct)
			if err := mgr(t, f).Create(context.Background(), "deploy", opts); err == nil {
				t.Errorf("Create(%+v) = nil, want a field-validation error", opts)
			}
			noRun(t, f)
		})
	}
}

func TestModify_RejectsFieldInjection(t *testing.T) {
	cases := map[string]ModifyOptions{
		"newline in comment":     {Comment: "x\ny"},
		"colon in shell":         {Shell: "/bin/sh:x"},
		"comma in primary group": {PrimaryGroup: "a,b"},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			f := exectest.New(exec.Direct)
			if err := mgr(t, f).Modify(context.Background(), "deploy", opts); err == nil {
				t.Errorf("Modify(%+v) = nil, want a field-validation error", opts)
			}
			noRun(t, f)
		})
	}
}

// A clean Comment with GECOS commas (the legitimate sub-field separator) must be
// accepted — the validation rejects the dangerous bytes, not normal content.
func TestCreate_AllowsCommasInComment(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).Create(context.Background(), "deploy",
		CreateOptions{Comment: "Jane Doe,Room 1,555-1234"}); err != nil {
		t.Fatalf("Create with a comma-bearing GECOS comment = %v, want nil", err)
	}
	if n := len(f.Calls()); n != 1 {
		t.Fatalf("ran %d commands, want 1 useradd", n)
	}
}
