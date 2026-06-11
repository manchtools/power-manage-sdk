package reboot

import (
	"slices"
	"testing"
)

// shutdownRebootArgs must place a "--" before the TIME/WALL positionals so
// a delay or broadcast message beginning with "-" can't be reparsed as a
// shutdown option (e.g. -c cancel or -h halt instead of -r reboot).
func TestShutdownRebootArgs_SeparatesPositionals(t *testing.T) {
	if got, want := shutdownRebootArgs("+5", "save your work"), []string{"-r", "--", "+5", "save your work"}; !slices.Equal(got, want) {
		t.Errorf("shutdownRebootArgs = %v, want %v", got, want)
	}
	// Empty delay defaults to +1; empty message is omitted.
	if got, want := shutdownRebootArgs("", ""), []string{"-r", "--", "+1"}; !slices.Equal(got, want) {
		t.Errorf("shutdownRebootArgs(empty) = %v, want %v", got, want)
	}
	// A flag-shaped message must land after the marker.
	got := shutdownRebootArgs("+0", "-c")
	if i := slices.Index(got, "--"); i < 0 || slices.Index(got, "-c") < i {
		t.Errorf("flag-shaped message not protected by --: %v", got)
	}
}
