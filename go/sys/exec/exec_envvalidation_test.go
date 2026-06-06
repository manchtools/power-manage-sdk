package exec_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// TestRunStreaming_RejectsLDPRELOAD pins finding #8 of the SDK audit
// (2026-06-06): RunStreaming must refuse to forward LD_PRELOAD even
// when a caller mistakenly passes it. The error returned is
// ErrBlockedEnvVar so callers can branch (e.g. report it as a
// security violation in a logged audit event) instead of treating it
// as a generic exec failure.
func TestRunStreaming_RejectsLDPRELOAD(t *testing.T) {
	_, err := pmexec.RunStreaming(context.Background(), "true", nil,
		[]string{"LD_PRELOAD=/tmp/evil.so"}, "", nil)
	if !errors.Is(err, pmexec.ErrBlockedEnvVar) {
		t.Fatalf("err = %v, want ErrBlockedEnvVar", err)
	}
}

// TestRunStreaming_RejectsPATHOverride proves that user-supplied PATH
// values are blocked at the boundary. The SDK-internal PATH prepend
// (which uses the agent's own environment) still works — see
// TestRunStreaming_PrependsInheritedPATH.
func TestRunStreaming_RejectsPATHOverride(t *testing.T) {
	_, err := pmexec.RunStreaming(context.Background(), "true", nil,
		[]string{"PATH=/tmp/attacker"}, "", nil)
	if !errors.Is(err, pmexec.ErrBlockedEnvVar) {
		t.Fatalf("err = %v, want ErrBlockedEnvVar", err)
	}
}

func TestRunStreaming_RejectsBASHENV(t *testing.T) {
	_, err := pmexec.RunStreaming(context.Background(), "true", nil,
		[]string{"BASH_ENV=/tmp/evil.sh"}, "", nil)
	if !errors.Is(err, pmexec.ErrBlockedEnvVar) {
		t.Fatalf("err = %v, want ErrBlockedEnvVar", err)
	}
}

func TestRunStreaming_RejectsGCONVPATH(t *testing.T) {
	_, err := pmexec.RunStreaming(context.Background(), "true", nil,
		[]string{"GCONV_PATH=/tmp/evil"}, "", nil)
	if !errors.Is(err, pmexec.ErrBlockedEnvVar) {
		t.Fatalf("err = %v, want ErrBlockedEnvVar", err)
	}
}

func TestRunStreaming_RejectsLDLibraryPath(t *testing.T) {
	_, err := pmexec.RunStreaming(context.Background(), "true", nil,
		[]string{"LD_LIBRARY_PATH=/tmp/evil"}, "", nil)
	if !errors.Is(err, pmexec.ErrBlockedEnvVar) {
		t.Fatalf("err = %v, want ErrBlockedEnvVar", err)
	}
}

func TestRunStreaming_RejectsMalformedEntry(t *testing.T) {
	_, err := pmexec.RunStreaming(context.Background(), "true", nil,
		[]string{"NOTKEY_EQUALS_VALUE"}, "", nil)
	if !errors.Is(err, pmexec.ErrInvalidEnvVar) {
		t.Fatalf("err = %v, want ErrInvalidEnvVar", err)
	}
}

// TestRunStreaming_AcceptsSafeVar is the inverse contract: a name not
// on the blocklist must pass through and be visible to the child.
func TestRunStreaming_AcceptsSafeVar(t *testing.T) {
	res, err := pmexec.RunStreaming(context.Background(), "sh",
		[]string{"-c", "echo -n $PM_AUDIT_TEST_MARKER"}, []string{"PM_AUDIT_TEST_MARKER=ok"}, "", nil)
	if err != nil {
		t.Fatalf("RunStreaming: %v", err)
	}
	// RunStreaming's recordLine pipeline appends a trailing newline
	// per captured line; assert on the trimmed payload.
	if got := strings.TrimSpace(res.Stdout); got != "ok" {
		t.Fatalf("child did not see the safe env var: stdout=%q (trimmed=%q)", res.Stdout, got)
	}
}
