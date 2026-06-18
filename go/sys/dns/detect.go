package dns

import (
	"context"
	osexec "os/exec"
)

// lookPath is a package-var seam so Detect is deterministically testable.
var lookPath = osexec.LookPath

// Detect reports the DNS backends usable on THIS host: Resolved when resolvectl
// is on PATH, NetworkManager when nmcli is. It lists; it never picks and never
// constructs a Manager — the consumer reads the list, picks a backend
// explicitly, and passes it to New. An empty slice means no usable DNS manager.
//
// The ctx is accepted for signature uniformity with the other capability Detect
// functions; the probe itself is a pure PATH lookup.
func Detect(ctx context.Context) []Backend {
	_ = ctx
	var out []Backend
	if _, err := lookPath("resolvectl"); err == nil {
		out = append(out, Resolved)
	}
	if _, err := lookPath("nmcli"); err == nil {
		out = append(out, NetworkManager)
	}
	return out
}
