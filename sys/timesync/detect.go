package timesync

import (
	"context"
	osexec "os/exec"
)

// lookPath is a package-var seam so Detect is deterministically testable.
var lookPath = osexec.LookPath

// Detect reports the time-sync backends usable on THIS host: Timedatectl when
// timedatectl is on PATH, Chrony when chronyc is. It lists; it never picks. The
// consumer reads the list, picks one, and passes it to New.
//
// The ctx is accepted for signature uniformity; the probe is a pure PATH lookup.
func Detect(ctx context.Context) []Backend {
	_ = ctx
	var out []Backend
	if _, err := lookPath("timedatectl"); err == nil {
		out = append(out, Timedatectl)
	}
	if _, err := lookPath("chronyc"); err == nil {
		out = append(out, Chrony)
	}
	return out
}
