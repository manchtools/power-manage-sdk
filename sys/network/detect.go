package network

import (
	"context"
	osexec "os/exec"
)

// lookPath is a package-var seam so Detect is deterministically testable.
var lookPath = osexec.LookPath

// Detect reports the WiFi backends usable on THIS host: NetworkManager when nmcli
// is on PATH. It lists; it never picks and never constructs a Manager — the
// consumer reads the list, picks a backend explicitly, and passes it to New. An
// empty slice means no usable WiFi manager (the consumer falls through to its
// "wifi not supported" path). This folds the old IsAvailable probe.
//
// The ctx is accepted for signature uniformity with the other capability Detect
// functions; the present probe is a pure PATH lookup.
func Detect(ctx context.Context) []Backend {
	_ = ctx
	if _, err := lookPath("nmcli"); err != nil {
		return nil
	}
	return []Backend{NetworkManager}
}
