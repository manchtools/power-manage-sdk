package exec

import (
	"slices"
	"testing"
)

// SeparatePositionals exists so a value that happens to begin with "-"
// (a username, device path, notification title, …) is always parsed by
// the target CLI as an operand, never as a flag. The contract: the "--"
// end-of-options marker is inserted exactly once, immediately after the
// flags and before every positional.

func TestSeparatePositionals_InsertsMarkerBeforePositionals(t *testing.T) {
	got := SeparatePositionals([]string{"-r", "-m"}, "alice")
	want := []string{"-r", "-m", "--", "alice"}
	if !slices.Equal(got, want) {
		t.Errorf("SeparatePositionals = %v, want %v", got, want)
	}
}

func TestSeparatePositionals_NoFlags(t *testing.T) {
	got := SeparatePositionals(nil, "/dev/sda3")
	want := []string{"--", "/dev/sda3"}
	if !slices.Equal(got, want) {
		t.Errorf("SeparatePositionals = %v, want %v", got, want)
	}
}

func TestSeparatePositionals_MultiplePositionals(t *testing.T) {
	got := SeparatePositionals([]string{"-u", "critical"}, "title", "body")
	want := []string{"-u", "critical", "--", "title", "body"}
	if !slices.Equal(got, want) {
		t.Errorf("SeparatePositionals = %v, want %v", got, want)
	}
}

// A flag-shaped positional must end up AFTER the marker so it can't be
// read as an option — this is the whole point.
func TestSeparatePositionals_FlagShapedPositionalIsAfterMarker(t *testing.T) {
	got := SeparatePositionals([]string{"-L"}, "-evil")
	want := []string{"-L", "--", "-evil"}
	if !slices.Equal(got, want) {
		t.Errorf("SeparatePositionals = %v, want %v", got, want)
	}
}

// The helper must not write into the caller's flags backing array.
func TestSeparatePositionals_DoesNotAliasCallerSlice(t *testing.T) {
	flags := make([]string, 1, 8) // spare capacity → naive append would alias
	flags[0] = "-r"
	_ = SeparatePositionals(flags, "alice")
	if len(flags) != 1 || flags[0] != "-r" {
		t.Errorf("caller flags mutated: %v", flags)
	}
}
