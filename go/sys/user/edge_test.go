package user

import (
	"context"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

// --- Weird / malformed tool output ---------------------------------------

// A passwd entry with a non-numeric UID is malformed; Get fails closed rather
// than silently treating it as UID 0 (root).
func TestGet_NonNumericUIDFailsClosed(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "deploy:x:NOTANUMBER:1000:Deploy:/home/deploy:/bin/bash\n"}, nil)
	if _, err := mgr(t, f).Get(context.Background(), "deploy"); err == nil {
		t.Error("Get accepted a non-numeric UID; want a fail-closed error")
	}
}

func TestGet_NonNumericGIDFailsClosed(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "deploy:x:1000:NOTANUMBER:Deploy:/home/deploy:/bin/bash\n"}, nil)
	if _, err := mgr(t, f).Get(context.Background(), "deploy"); err == nil {
		t.Error("Get accepted a non-numeric GID; want a fail-closed error")
	}
}

// A '*'-prefixed shadow password (a common disabled-account marker) is detected
// as locked, the same as '!'.
func TestGet_StarLockedIsDetected(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "deploy:x:1000:1000::/home/deploy:/bin/bash\n"}, nil)
	f.Push(exec.Result{Stdout: "deploy:x:1000:\n"}, nil)
	f.Push(exec.Result{Stdout: "deploy\n"}, nil)
	f.Push(exec.Result{Stdout: "deploy:*:19000:0:99999:7:::\n"}, nil)
	info, err := mgr(t, f).Get(context.Background(), "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Locked {
		t.Error("'*'-prefixed shadow entry not detected as locked")
	}
}

// Get tolerates extra surrounding whitespace / CR in getent output.
func TestGet_TrimsWhitespaceAndCR(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "  deploy:x:1000:1000:Deploy:/home/deploy:/bin/bash\r\n"}, nil)
	f.Push(exec.Result{Stdout: "deploy:x:1000:\n"}, nil)
	f.Push(exec.Result{Stdout: "deploy\n"}, nil)
	f.Push(exec.Result{Stdout: "deploy:$6$x:::::::\n"}, nil)
	info, err := mgr(t, f).Get(context.Background(), "deploy")
	if err != nil {
		t.Fatalf("Get with padded output: %v", err)
	}
	if info.UID != 1000 || info.Shell != "/bin/bash" {
		t.Errorf("Info = %+v, want UID 1000 / /bin/bash despite padding", info)
	}
}

// A group line with stray empty member entries ("a,,b") must not yield a "".
func TestGroupMembers_FiltersEmptyEntries(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "docker:x:999:deploy,,ops,\n"}, nil)
	members, err := mgr(t, f).GroupMembers(context.Background(), "docker")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(members, ",") != "deploy,ops" {
		t.Errorf("members = %v, want [deploy ops] with empties filtered", members)
	}
}

// A members field that is ALL separators ("docker:x:999:,,") yields no members.
func TestGroupMembers_AllEmptyEntriesIsNil(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "docker:x:999:,,\n"}, nil)
	members, err := mgr(t, f).GroupMembers(context.Background(), "docker")
	if err != nil || members != nil {
		t.Errorf("GroupMembers = (%v,%v), want (nil,nil) for an all-separators field", members, err)
	}
}

// --- Weird-but-valid inputs ----------------------------------------------

// A password may legitimately contain colons; chpasswd splits on the FIRST
// colon, so the whole "pass:word" reaches the password field intact.
func TestSetPassword_ColonInPasswordIsPreserved(t *testing.T) {
	f := exectest.New(exec.Direct)
	secret, err := exec.NewSecret("p@ss:w0rd:with:colons")
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr(t, f).SetPassword(context.Background(), "deploy", secret); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f.Calls()[0].Stdin)
	if string(got) != "deploy:p@ss:w0rd:with:colons" {
		t.Errorf("chpasswd stdin = %q, want the colon-bearing password intact", got)
	}
}

// GeneratePassword succeeds at the exact length bounds.
func TestGeneratePassword_ExactBounds(t *testing.T) {
	for _, n := range []int{MinPasswordLength, MaxPasswordLength} {
		s, err := GeneratePassword(n, ComplexityComplex)
		if err != nil {
			t.Fatalf("GeneratePassword(%d): %v", n, err)
		}
		if len(s.Reveal()) != n {
			t.Errorf("length = %d, want %d", len(s.Reveal()), n)
		}
	}
}

// The (practically unreachable) RNG-failure path returns a wrapped error rather
// than a short/empty password. Exercised via the randInt seam.
func TestGeneratePassword_RNGFailure(t *testing.T) {
	restore := randInt
	randInt = func(io.Reader, *big.Int) (*big.Int, error) {
		return nil, io.ErrUnexpectedEOF
	}
	defer func() { randInt = restore }()

	if _, err := GeneratePassword(16, ComplexityAlphanumeric); err == nil {
		t.Error("GeneratePassword returned nil error when the RNG failed")
	}
}
