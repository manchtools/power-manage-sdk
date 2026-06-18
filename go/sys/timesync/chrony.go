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
	if len(f) < chronyTrackingFields {
		return Status{}, fmt.Errorf("timesync: unexpected chronyc tracking format (%d fields, want %d)", len(f), chronyTrackingFields)
	}
	st := Status{
		Enabled: true, // chronyc answered, so the daemon is running
		Source:  f[1],
		// Leap status "Not synchronised" is the only unsynced value; "Normal" and
		// the leap-second variants all mean the clock is disciplined.
		Synchronized: f[13] != "Not synchronised",
	}
	if off, err := strconv.ParseFloat(f[4], 64); err == nil {
		st.OffsetSeconds = off
	}
	return st, nil
}
