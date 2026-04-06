package cron

import (
	"testing"
	"time"
)

func TestNextTime(t *testing.T) {
	loc := time.UTC
	ref := time.Date(2026, 4, 4, 10, 30, 0, 0, loc) // Saturday 2026-04-04 10:30 UTC

	tests := []struct {
		name string
		expr string
		want time.Time
	}{
		{
			name: "every minute",
			expr: "* * * * *",
			want: time.Date(2026, 4, 4, 10, 31, 0, 0, loc),
		},
		{
			name: "daily at 3am",
			expr: "0 3 * * *",
			want: time.Date(2026, 4, 5, 3, 0, 0, 0, loc),
		},
		{
			name: "every 8 hours",
			expr: "0 */8 * * *",
			want: time.Date(2026, 4, 4, 16, 0, 0, 0, loc),
		},
		{
			name: "midnight daily",
			expr: "0 0 * * *",
			want: time.Date(2026, 4, 5, 0, 0, 0, 0, loc),
		},
		{
			name: "hourly at :00",
			expr: "0 * * * *",
			want: time.Date(2026, 4, 4, 11, 0, 0, 0, loc),
		},
		{
			name: "every 15 minutes",
			expr: "*/15 * * * *",
			want: time.Date(2026, 4, 4, 10, 45, 0, 0, loc),
		},
		{
			name: "sunday at 3am",
			expr: "0 3 * * 0",
			want: time.Date(2026, 4, 5, 3, 0, 0, 0, loc), // Apr 5 is Sunday
		},
		{
			name: "first of month at 3am",
			expr: "0 3 1 * *",
			want: time.Date(2026, 5, 1, 3, 0, 0, 0, loc),
		},
		{
			name: "weekdays at 9am",
			expr: "0 9 * * 1-5",
			want: time.Date(2026, 4, 6, 9, 0, 0, 0, loc), // Monday
		},
		{
			name: "specific minutes",
			expr: "15,45 * * * *",
			want: time.Date(2026, 4, 4, 10, 45, 0, 0, loc),
		},
		{
			name: "specific months jan and jul",
			expr: "0 0 1 1,7 *",
			want: time.Date(2026, 7, 1, 0, 0, 0, 0, loc),
		},
		{
			name: "end of hour",
			expr: "59 * * * *",
			want: time.Date(2026, 4, 4, 10, 59, 0, 0, loc),
		},
		{
			name: "every 5 minutes",
			expr: "*/5 * * * *",
			want: time.Date(2026, 4, 4, 10, 35, 0, 0, loc),
		},
		{
			name: "dom and dow both specified uses OR",
			expr: "0 12 15 * 1", // 15th of month OR Monday
			want: time.Date(2026, 4, 6, 12, 0, 0, 0, loc), // Monday Apr 6
		},
		{
			name: "exact minute boundary skipped",
			expr: "30 10 * * *",
			want: time.Date(2026, 4, 5, 10, 30, 0, 0, loc), // next day, since ref is exactly 10:30
		},
		{
			name: "step on hours",
			expr: "0 */6 * * *",
			want: time.Date(2026, 4, 4, 12, 0, 0, 0, loc),
		},
		{
			name: "range with step equivalent */1",
			expr: "* * * * 0-6",
			want: time.Date(2026, 4, 4, 10, 31, 0, 0, loc),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NextTime(tt.expr, ref)
			if err != nil {
				t.Fatalf("NextTime(%q) error: %v", tt.expr, err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("NextTime(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestNextTime_PreservesTimezone(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	ref := time.Date(2026, 4, 4, 10, 30, 0, 0, berlin)
	got, err := NextTime("0 3 * * *", ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.Location() != berlin {
		t.Errorf("expected timezone %v, got %v", berlin, got.Location())
	}
	want := time.Date(2026, 4, 5, 3, 0, 0, 0, berlin)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNextTime_Invalid(t *testing.T) {
	ref := time.Now()

	invalid := []string{
		"",
		"* * *",
		"* * * * * *",
		"60 * * * *",
		"* 25 * * *",
		"* * 32 * *",
		"* * * 13 *",
		"* * * * 7",
		"abc * * * *",
		"*/0 * * * *",
		"*/-1 * * * *",
		"5-3 * * * *", // inverted range
	}

	for _, expr := range invalid {
		_, err := NextTime(expr, ref)
		if err == nil {
			t.Errorf("NextTime(%q) expected error, got nil", expr)
		}
	}
}

func TestParseField(t *testing.T) {
	tests := []struct {
		field    string
		min, max int
		want     []int
	}{
		{"*", 0, 5, []int{0, 1, 2, 3, 4, 5}},
		{"*/2", 0, 5, []int{0, 2, 4}},
		{"1,3,5", 0, 5, []int{1, 3, 5}},
		{"1-3", 0, 5, []int{1, 2, 3}},
		{"0", 0, 59, []int{0}},
		{"*/3", 0, 11, []int{0, 3, 6, 9}},
		{"1,2,3-5", 0, 10, []int{1, 2, 3, 4, 5}},
	}

	for _, tt := range tests {
		set, err := parseField(tt.field, tt.min, tt.max)
		if err != nil {
			t.Fatalf("parseField(%q, %d, %d) error: %v", tt.field, tt.min, tt.max, err)
		}
		for _, v := range tt.want {
			if !set[v] {
				t.Errorf("parseField(%q) missing %d", tt.field, v)
			}
		}
		if len(set) != len(tt.want) {
			t.Errorf("parseField(%q) got %d values, want %d", tt.field, len(set), len(tt.want))
		}
	}
}

func TestIsFullRange(t *testing.T) {
	full := map[int]bool{0: true, 1: true, 2: true, 3: true}
	if !isFullRange(full, 0, 3) {
		t.Error("expected full range")
	}

	partial := map[int]bool{0: true, 2: true}
	if isFullRange(partial, 0, 3) {
		t.Error("expected not full range")
	}
}
