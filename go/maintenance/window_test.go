package maintenance_test

import (
	"errors"
	"testing"
	"time"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/maintenance"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		w       *pmv1.MaintenanceWindow
		wantErr bool
	}{
		{"nil window", nil, false},
		{"empty schedule", &pmv1.MaintenanceWindow{}, false},
		{
			"valid same-day",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: []string{"mon", "tue"}, Allow: "09:00-17:00"},
			}},
			false,
		},
		{
			"valid crosses midnight",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: []string{"fri"}, Allow: "22:00-06:00"},
			}},
			false,
		},
		{
			"bad day",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: []string{"funday"}, Allow: "00:00-23:59"},
			}},
			true,
		},
		{
			// Mixed-case tokens are rejected by Validate so they cannot
			// silently round-trip through the projector and then never
			// match at runtime. Callers must lowercase before calling.
			"uppercase day rejected",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: []string{"MON"}, Allow: "09:00-17:00"},
			}},
			true,
		},
		{
			"mixed-case day rejected",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: []string{"Mon"}, Allow: "09:00-17:00"},
			}},
			true,
		},
		{
			"duplicate day",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: []string{"mon", "mon"}, Allow: "09:00-17:00"},
			}},
			true,
		},
		{
			"empty days",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: nil, Allow: "09:00-17:00"},
			}},
			true,
		},
		{
			"bad clock",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: []string{"mon"}, Allow: "25:00-26:00"},
			}},
			true,
		},
		{
			"missing dash",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: []string{"mon"}, Allow: "09:0017:00X"},
			}},
			true,
		},
		{
			"zero-length range",
			&pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
				{Days: []string{"mon"}, Allow: "09:00-09:00"},
			}},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := maintenance.Validate(tc.w)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil")
				}
				if !errors.Is(err, maintenance.ErrInvalidEntry) && tc.w != nil {
					t.Fatalf("want ErrInvalidEntry chain, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestIsAllowedSameDay(t *testing.T) {
	w := &pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
		{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Allow: "09:00-17:00"},
	}}
	// Monday 2026-05-04 — note May 3 (today's date in conv context) is Sunday.
	mondayNoon := time.Date(2026, time.May, 4, 12, 0, 0, 0, time.UTC)
	if !maintenance.IsAllowed(w, mondayNoon) {
		t.Fatalf("want allowed at Mon noon")
	}
	mondayStart := time.Date(2026, time.May, 4, 9, 0, 0, 0, time.UTC)
	if !maintenance.IsAllowed(w, mondayStart) {
		t.Fatalf("want allowed at Mon 09:00 (start is inclusive)")
	}
	mondayEarly := time.Date(2026, time.May, 4, 8, 59, 0, 0, time.UTC)
	if maintenance.IsAllowed(w, mondayEarly) {
		t.Fatalf("want denied at Mon 08:59 (one minute before window)")
	}
	mondayEnd := time.Date(2026, time.May, 4, 17, 0, 0, 0, time.UTC)
	if maintenance.IsAllowed(w, mondayEnd) {
		t.Fatalf("want denied at Mon 17:00 (end is exclusive)")
	}
	saturday := time.Date(2026, time.May, 9, 12, 0, 0, 0, time.UTC)
	if maintenance.IsAllowed(w, saturday) {
		t.Fatalf("want denied on Saturday")
	}
}

func TestIsAllowedCrossesMidnight(t *testing.T) {
	w := &pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
		{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Allow: "22:00-06:00"},
	}}
	// Monday 22:00 — exactly the window start. Inclusive boundary
	// proves the agent fires on the very first second of the window
	// rather than waiting one minute before becoming due.
	if !maintenance.IsAllowed(w, time.Date(2026, time.May, 4, 22, 0, 0, 0, time.UTC)) {
		t.Fatalf("want allowed at Mon 22:00 (cross-midnight start is inclusive)")
	}
	// Monday 23:00 — covered by the Mon entry's pre-midnight half.
	if !maintenance.IsAllowed(w, time.Date(2026, time.May, 4, 23, 0, 0, 0, time.UTC)) {
		t.Fatalf("want allowed at Mon 23:00")
	}
	// Tuesday 02:00 — covered by the *Mon* entry's post-midnight tail.
	// The tail belongs to the day-listed-as-yesterday (Mon), not Tue.
	if !maintenance.IsAllowed(w, time.Date(2026, time.May, 5, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("want allowed at Tue 02:00 (tail of Mon's window)")
	}
	// Tuesday 06:00 — outside (end exclusive).
	if maintenance.IsAllowed(w, time.Date(2026, time.May, 5, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("want denied at Tue 06:00")
	}
	// Saturday 02:00 — Friday's window covers this (Friday is listed,
	// Sat is the day-after, so Sat 02:00 is the post-midnight tail).
	if !maintenance.IsAllowed(w, time.Date(2026, time.May, 9, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("want allowed at Sat 02:00 (tail of Fri's window)")
	}
	// Sunday 02:00 — Saturday is NOT listed, so the tail does not
	// apply: Sat midnight->Sun morning is not covered.
	if maintenance.IsAllowed(w, time.Date(2026, time.May, 10, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("want denied at Sun 02:00 (Saturday not listed)")
	}
}

func TestUnion(t *testing.T) {
	weekdays := &pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
		{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Allow: "22:00-06:00"},
	}}
	weekends := &pmv1.MaintenanceWindow{Schedule: []*pmv1.MaintenanceWindowEntry{
		{Days: []string{"sat", "sun"}, Allow: "00:00-23:59"},
	}}
	empty := &pmv1.MaintenanceWindow{}

	got := maintenance.Union(weekdays, weekends)
	if len(got.GetSchedule()) != 2 {
		t.Fatalf("want 2 entries in concatenation, got %d", len(got.GetSchedule()))
	}
	// Saturday afternoon is allowed by the weekends entry but not by
	// the weekdays one — proves the OR semantics across windows.
	satAfternoon := time.Date(2026, time.May, 9, 14, 0, 0, 0, time.UTC)
	if !maintenance.IsAllowed(got, satAfternoon) {
		t.Fatalf("want allowed Sat 14:00 in union")
	}

	// Empty input collapses union to "always allowed" — a group with
	// no window contributes no constraint.
	collapsed := maintenance.Union(weekdays, empty)
	if len(collapsed.GetSchedule()) != 0 {
		t.Fatalf("want empty union when any input is empty, got %d entries", len(collapsed.GetSchedule()))
	}
	if !maintenance.IsAllowed(collapsed, satAfternoon) {
		t.Fatalf("empty union must allow any moment")
	}

	// Nil input behaves like empty.
	collapsedNil := maintenance.Union(weekdays, nil)
	if len(collapsedNil.GetSchedule()) != 0 {
		t.Fatalf("nil input should collapse union, got %d entries", len(collapsedNil.GetSchedule()))
	}
}

func TestIsAllowedNilOrEmpty(t *testing.T) {
	now := time.Now()
	if !maintenance.IsAllowed(nil, now) {
		t.Fatalf("nil window must allow")
	}
	if !maintenance.IsAllowed(&pmv1.MaintenanceWindow{}, now) {
		t.Fatalf("empty schedule must allow")
	}
}
