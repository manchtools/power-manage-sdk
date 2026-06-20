//go:build integration

package log_test

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	syslog "github.com/manchtools/power-manage-sdk/sys/log"
)

func systemdRunning() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func newJournald(t *testing.T) syslog.Source {
	t.Helper()
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	s, err := syslog.New(syslog.Journald, r)
	if err != nil {
		t.Fatalf("New(Journald): %v", err)
	}
	return s
}

// READ-ONLY: Detect + a small real Query against journald. Under a real systemd
// (the test-sys container, where power-manage is in the systemd-journal group)
// the Query MUST succeed and return real journal lines — the drift guard against
// a journalctl output change. Elsewhere it skips gracefully.
func TestQuery_Integration(t *testing.T) {
	for _, b := range syslog.Detect(context.Background()) {
		if b != syslog.Journald && b != syslog.Syslog {
			t.Errorf("Detect returned unexpected backend %v", b)
		}
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl not present")
	}
	s := newJournald(t)
	lines, err := s.Query(context.Background(), syslog.Query{Lines: 5})
	if systemdRunning() {
		if err != nil {
			t.Fatalf("journalctl Query under systemd: %v", err)
		}
		if len(lines) == 0 {
			t.Fatal("journalctl returned no lines under systemd (journal-group access missing, or empty journal)")
		}
		t.Logf("journalctl returned %d line(s)", len(lines))
		return
	}
	if err != nil {
		t.Skipf("journalctl read unusable here (no privilege/journal): %v", err)
	}
}

// TestQuery_GrepSeed_Integration is the FILTER drift guard: it seeds a uniquely
// tagged entry into the real journal (`logger`), then drives the SDK's
// Query{Grep} (real `journalctl --grep`) and asserts that exact entry comes
// back. Unlike TestQuery_Integration (which only checks the journal is
// non-empty), this proves the --grep filter path returns the matching content —
// a change to journalctl's --grep semantics or output framing is caught here.
func TestQuery_GrepSeed_Integration(t *testing.T) {
	if !systemdRunning() {
		t.Skip("no live systemd journal to seed (needs the test-sys container)")
	}
	if _, err := exec.LookPath("logger"); err != nil {
		t.Skip("logger not present; cannot seed a journal entry")
	}

	// Unique per process so a re-run never matches a stale entry; PID needs no
	// clock/random and is stable within one container run.
	marker := "PM-LOG-SEED-" + strconv.Itoa(os.Getpid())
	if out, err := exec.Command("logger", "-t", "pm-sdk-test", marker).CombinedOutput(); err != nil {
		t.Skipf("cannot seed journal via logger: %v\n%s", err, out)
	}

	s := newJournald(t)
	ctx := context.Background()

	// journald ingests /dev/log asynchronously; poll briefly for the entry to
	// land rather than asserting on the first read. (time.Sleep is fine in a
	// test — the clock seam is production-only.)
	var lines []string
	var lastErr error
	for i := 0; i < 20; i++ {
		var err error
		lines, err = s.Query(ctx, syslog.Query{Grep: marker, Lines: 50})
		if err != nil {
			lastErr, lines = err, nil
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if len(lines) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(lines) == 0 {
		if lastErr != nil {
			t.Fatalf("Query{Grep} against real journalctl: %v", lastErr)
		}
		t.Fatalf("seeded marker %q never returned by Query{Grep} — real journalctl --grep filter drifted?", marker)
	}

	// Filter proof: EVERY returned line is the seeded entry (the unique marker),
	// so --grep genuinely EXCLUDED the rest of the journal rather than no-op'ing
	// and returning everything.
	for _, ln := range lines {
		if !strings.Contains(ln, marker) {
			t.Errorf("Query{Grep:%q} returned a non-matching line %q — --grep is not filtering", marker, ln)
		}
	}

	// Exclusion proof: a marker that was never logged returns ZERO entries — and
	// the SDK drops journalctl's "-- No entries --" status marker (not a real
	// entry) rather than surfacing it as one.
	absent := "PM-LOG-ABSENT-" + strconv.Itoa(os.Getpid())
	ghost, err := s.Query(ctx, syslog.Query{Grep: absent, Lines: 50})
	if err != nil {
		t.Fatalf("Query{Grep:absent}: %v", err)
	}
	if len(ghost) != 0 {
		t.Errorf("Query{Grep:%q} for an unlogged marker returned %d line(s) — --grep not excluding or status marker leaked: %v", absent, len(ghost), ghost)
	}
}
