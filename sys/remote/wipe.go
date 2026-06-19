package remote

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// wipeDest is the shared Wipe implementation used by every Source. The
// per-source Wipe methods are thin forwarders so the contract — "refuse
// anything not under a managed root or previously recorded; otherwise
// rm -rf with the usual safety guards" — is in one place.
func wipeDest(_ context.Context, dest string) error {
	if err := canWipe(dest); err != nil {
		return err
	}
	if err := os.RemoveAll(dest); err != nil {
		// ENOENT is the "already gone" case; treat it as a successful
		// no-op so the cycle re-runs after a previous Wipe stay clean.
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("remove %s: %w", dest, err)
	}
	// Drop the dest from the recorded set so a future RecordDest call
	// for the same path doesn't keep a stale entry alive in memory.
	forgetDest(dest)
	return nil
}
