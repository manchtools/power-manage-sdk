package timesync

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// chronyManager queries chrony via `chronyc -c tracking` (CSV report).
type chronyManager struct {
	r exec.Runner
}

// Status reads chrony's tracking report.
func (m *chronyManager) Status(ctx context.Context) (Status, error) {
	out, err := runRead(ctx, m.r, "chronyc", "-c", "tracking")
	if err != nil {
		return Status{}, err
	}
	return parseChronyTracking(out)
}

// chronyTrackingFields is the field count of `chronyc -c tracking` CSV; the
// fields we read are: [1] reference source, [4] system-time offset (signed
// seconds), [13] leap status.
const chronyTrackingFields = 14

// parseChronyTracking parses the single-line CSV from `chronyc -c tracking`.
func parseChronyTracking(out string) (Status, error) {
	line := strings.TrimSpace(out)
	if line == "" {
		return Status{}, fmt.Errorf("timesync: empty chronyc tracking output")
	}
	f := strings.Split(line, ",")
	// Require AT LEAST the known field count (not exactly): chrony's CSV is not
	// guaranteed fixed across versions, and a newer version can append trailing
	// fields — those are harmless since we read by fixed leading index. A short
	// line, however, means a layout we don't understand → fail closed. The
	// leap-status check below is the real schema-drift guard (a reordered layout
	// yields an unrecognised leap value).
	if len(f) < chronyTrackingFields {
		return Status{}, fmt.Errorf("timesync: unexpected chronyc tracking format (%d fields, want >= %d)", len(f), chronyTrackingFields)
	}
	st := Status{
		Enabled: true, // chronyc answered, so the daemon is running
		Source:  f[1],
	}
	// Validate the leap status against chrony's known set rather than a bare
	// inequality: an unrecognised value means the CSV schema drifted, so fail
	// closed instead of silently reporting "synchronized".
	switch strings.TrimSpace(f[13]) {
	case "Not synchronised":
		st.Synchronized = false
	case "Normal", "Insert second", "Delete second":
		st.Synchronized = true
	default:
		return Status{}, fmt.Errorf("timesync: unrecognised chronyc leap status %q (CSV schema drift?)", strings.TrimSpace(f[13]))
	}
	if off, err := strconv.ParseFloat(f[4], 64); err == nil {
		st.OffsetSeconds = off
	}
	return st, nil
}
