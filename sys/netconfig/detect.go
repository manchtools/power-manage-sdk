package netconfig

import (
	"context"
	osexec "os/exec"
)

// lookPath is a package-var seam so Detect is deterministically testable.
var lookPath = osexec.LookPath

// Detect reports the interface-config backends usable on THIS host:
// NetworkManager when nmcli is on PATH, SystemdNetworkd when networkctl is. It
// lists; it never picks and never constructs a Manager — the consumer reads the
// list, picks a backend explicitly, and passes it to New. An empty slice means
// no usable interface-config manager.
//
// The ctx is accepted for signature uniformity with the other capability Detect
// functions; the probe itself is a pure PATH lookup.
func Detect(ctx context.Context) []Backend {
	_ = ctx
	var out []Backend
	if _, err := lookPath("nmcli"); err == nil {
		out = append(out, NetworkManager)
	}
	if _, err := lookPath("networkctl"); err == nil {
		out = append(out, SystemdNetworkd)
	}
	return out
}
