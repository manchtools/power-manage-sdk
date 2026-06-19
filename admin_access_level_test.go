package sdk

// Wire-compat pin for AdminAccessLevel enum values. Adding values is
// additive and safe; reordering/renumbering is a wire break against
// every device already running. These tests fail fast when a future
// edit shifts a value, so the break is caught here, not at an
// in-the-field agent.
//
// Filed alongside the TerminalAdmin work in
// manchtools/power-manage-server#70 — the new TERMINAL_ADMIN_*
// values were added so the agent can route to two new sudoers
// generators without mutating FULL/LIMITED's existing semantics.

import (
	"testing"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

func TestAdminAccessLevel_WireNumbersAreStable(t *testing.T) {
	cases := []struct {
		name string
		got  int32
		want int32
	}{
		{"UNSPECIFIED", int32(pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_UNSPECIFIED), 0},
		{"FULL", int32(pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_FULL), 1},
		{"LIMITED", int32(pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_LIMITED), 2},
		{"CUSTOM", int32(pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_CUSTOM), 3},
		{"TERMINAL_ADMIN_LIMITED", int32(pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED), 4},
		{"TERMINAL_ADMIN_FULL", int32(pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL), 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("AdminAccessLevel %s = %d; want %d (wire-compat break)", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestAdminAccessLevel_TerminalAdminValuesAreDistinct guards against a
// future careless edit that re-uses an existing value for one of the
// new names. Both new values must be present and distinct from every
// older value.
func TestAdminAccessLevel_TerminalAdminValuesAreDistinct(t *testing.T) {
	tlim := pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED
	tfull := pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL

	olds := []pm.AdminAccessLevel{
		pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_UNSPECIFIED,
		pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_FULL,
		pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_LIMITED,
		pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_CUSTOM,
	}
	for _, o := range olds {
		if tlim == o {
			t.Fatalf("TERMINAL_ADMIN_LIMITED (%d) collides with pre-existing value %s (%d)", tlim, o, o)
		}
		if tfull == o {
			t.Fatalf("TERMINAL_ADMIN_FULL (%d) collides with pre-existing value %s (%d)", tfull, o, o)
		}
	}
	if tlim == tfull {
		t.Fatalf("TERMINAL_ADMIN_LIMITED and TERMINAL_ADMIN_FULL collide on %d", tlim)
	}
}

// TestAdminAccessLevel_TerminalAdminValuesHaveStringNames pins the
// generated .String() output so a future re-numbering can't drift the
// human label silently.
func TestAdminAccessLevel_TerminalAdminValuesHaveStringNames(t *testing.T) {
	if got := pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED.String(); got != "ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED" {
		t.Fatalf("TERMINAL_ADMIN_LIMITED.String() = %q; want %q", got, "ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED")
	}
	if got := pm.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL.String(); got != "ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL" {
		t.Fatalf("TERMINAL_ADMIN_FULL.String() = %q; want %q", got, "ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL")
	}
}
