package user

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These two guards together enforce — BY CONSTRUCTION, not by every method
// remembering — that no user-package method can issue an unbounded escalated
// command. That invariant was previously implemented per method (ensureCtx at the
// top of each), so the methods that forgot (Lock, Unlock, SetPassword,
// KillSessions, LastLogin) silently skipped it and no example-based test noticed.
//
//	1. exec applies ensureCtx (TestExecBoundsContext), and
//	2. every Runner call goes through exec (TestAllRunnerCallsRouteThroughExec).
//
// Add a new method that calls the Runner directly and (2) fails the build.

// TestExecBoundsContext: the single Runner chokepoint bounds a deadline-less ctx.
func TestExecBoundsContext(t *testing.T) {
	f := exectest.New(exec.Direct)
	su, ok := mgr(t, f).(*shadowUtils)
	require.True(t, ok, "Manager is not *shadowUtils")

	_, err := su.exec(context.Background(), exec.Command{Name: "true"})
	require.NoError(t, err)

	ctxs := f.CallContexts()
	require.Len(t, ctxs, 1, "exec must run exactly one command")
	_, hasDeadline := ctxs[0].Deadline()
	assert.True(t, hasDeadline, "exec must bound a deadline-less context via ensureCtx")
}

// TestExecPassesThroughADeadline: a caller-supplied deadline is preserved, not
// replaced — ensureCtx only ADDS a bound when one is missing.
func TestExecPassesThroughADeadline(t *testing.T) {
	f := exectest.New(exec.Direct)
	su := mgr(t, f).(*shadowUtils)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deadlineCtx, dlCancel := context.WithTimeout(ctx, 42*time.Second)
	defer dlCancel()
	want, _ := deadlineCtx.Deadline()

	_, err := su.exec(deadlineCtx, exec.Command{Name: "true"})
	require.NoError(t, err)
	got, ok := f.CallContexts()[0].Deadline()
	require.True(t, ok)
	assert.Equal(t, want, got, "an existing deadline must be preserved, not overwritten")
}

// TestAllRunnerCallsRouteThroughExec is the structural guard: every escalated /
// Runner call MUST flow through (*shadowUtils).exec, which bounds the context. It
// scans the package's NON-test source and asserts the raw Runner call `u.r.Run(`
// appears exactly once — inside exec. A future method that calls the Runner
// directly (and so could skip ensureCtx — exactly the Lock/Unlock regression)
// makes the count != 1 and fails the build. Self-discovering: no method list to
// keep in sync.
func TestAllRunnerCallsRouteThroughExec(t *testing.T) {
	src := nonTestPackageSource(t)
	require.NotEmpty(t, src, "no non-test source read — the scan is broken")
	n := strings.Count(src, "u.r.Run(")
	assert.Equalf(t, 1, n,
		"`u.r.Run(` must appear exactly once (inside exec); found %d. A direct Runner call bypasses the ctx-bounding chokepoint — route it through u.exec(...) instead.", n)
}

// nonTestPackageSource concatenates every non-_test .go file in the package dir.
func nonTestPackageSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	var b strings.Builder
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		require.NoError(t, err)
		b.Write(data)
	}
	return b.String()
}
