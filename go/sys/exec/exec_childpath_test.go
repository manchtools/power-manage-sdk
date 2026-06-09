package exec_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// RunStreamingChildPath is the TRUSTED seam for running with a curated
// PATH (the per-user runuser fan-out). The curated childPath must be the
// PATH the child sees — even though PATH is blocklisted from caller env.
func TestRunStreamingChildPath_AppliesCuratedPath(t *testing.T) {
	res, err := pmexec.RunStreamingChildPath(context.Background(), "sh",
		[]string{"-c", "printf %s \"$PATH\""}, []string{"MARKER=1"},
		"/curated/bin:/usr/bin", "", nil)
	if err != nil {
		t.Fatalf("RunStreamingChildPath: %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "/curated/bin:/usr/bin" {
		t.Fatalf("child PATH = %q, want the curated value", got)
	}
}

// SECURITY (the un-sandbox footgun): with EMPTY envVars the curated
// childPath must STILL be authoritative and the parent environment must
// NOT be inherited. The previous shape applied childPath only when
// envVars was non-empty, so an empty-env caller silently inherited the
// agent's (root's) full environment — including root's PATH — defeating
// the isolation the curated PATH exists to provide.
func TestRunStreamingChildPath_EmptyEnvStillIsolates(t *testing.T) {
	t.Setenv("PM_PARENT_SECRET", "leaked-from-root")

	res, err := pmexec.RunStreamingChildPath(context.Background(), "sh",
		[]string{"-c", "printf %s \"$PATH|${PM_PARENT_SECRET:-unset}\""},
		nil, "/curated/bin", "", nil)
	if err != nil {
		t.Fatalf("RunStreamingChildPath: %v", err)
	}
	got := strings.TrimSpace(res.Stdout)
	if got != "/curated/bin|unset" {
		t.Fatalf("empty-env curated run leaked the parent environment: got %q, want %q",
			got, "/curated/bin|unset")
	}
}

// The boundary check still applies on this entry point: a blocklisted
// env var (PATH, LD_PRELOAD, …) in envVars is refused, so an untrusted
// caller cannot smuggle one past the curated-PATH seam.
func TestRunStreamingChildPath_StillRejectsBlockedEnv(t *testing.T) {
	_, err := pmexec.RunStreamingChildPath(context.Background(), "true", nil,
		[]string{"LD_PRELOAD=/tmp/evil.so"}, "/usr/bin", "", nil)
	if !errors.Is(err, pmexec.ErrBlockedEnvVar) {
		t.Fatalf("err = %v, want ErrBlockedEnvVar", err)
	}
}

// Counterpart contract that the footgun fix must NOT regress: plain
// RunStreaming with EMPTY envVars keeps inheriting the parent
// environment fully (the long-standing behavior every Run*/Privileged*
// caller relies on). A marker set in the parent must be visible.
func TestRunStreaming_EmptyEnvInheritsParent(t *testing.T) {
	t.Setenv("PM_PARENT_MARKER", "inherited")

	res, err := pmexec.RunStreaming(context.Background(), "sh",
		[]string{"-c", "printf %s \"${PM_PARENT_MARKER:-unset}\""}, nil, "", nil)
	if err != nil {
		t.Fatalf("RunStreaming: %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "inherited" {
		t.Fatalf("RunStreaming empty-env must inherit the parent env; got %q", got)
	}
}
