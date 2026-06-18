package log

import (
	"context"
	osexec "os/exec"
)

// lookPath is a package-var seam so Detect is deterministically testable.
var lookPath = osexec.LookPath

// Detect reports the log backends usable on THIS host: Journald when journalctl
// is on PATH, Syslog when a classic log file exists. It lists; the consumer picks
// one and passes it to New.
//
// The ctx is accepted for signature uniformity; the probe is PATH/stat lookups.
func Detect(ctx context.Context) []Backend {
	_ = ctx
	var out []Backend
	if _, err := lookPath("journalctl"); err == nil {
		out = append(out, Journald)
	}
	if _, err := syslogPath(); err == nil {
		out = append(out, Syslog)
	}
	return out
}
