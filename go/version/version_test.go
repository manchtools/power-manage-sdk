package version

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input string
		want  Parts
	}{
		{"2026.04.07", Parts{2026, 4, 7, ""}},
		{"2026.4.7", Parts{2026, 4, 7, ""}},
		{"2026.04", Parts{2026, 4, 0, ""}},
		{"2026.04.07-rc1", Parts{2026, 4, 7, "rc1"}},
		{"2026.04.07-beta2", Parts{2026, 4, 7, "beta2"}},
		{"v2026.04.07", Parts{2026, 4, 7, ""}},
		{"dev", Parts{9999, 99, 99, "dev"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParse_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"abc",
		"2026",
		"2026.04.07.01",
		"2026.xx.07",
		"2026.04.07-",
		"2026.13.01",
		"2026.00.01",
		"2026.04.00",
		"10000.01.01",
	}
	for _, v := range invalid {
		if _, err := Parse(v); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", v)
		}
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// Equal
		{"2026.04.07", "2026.04.07", 0},
		{"2026.04", "2026.04", 0},

		// Year differs
		{"2027.01.01", "2026.12.31", 1},
		{"2025.12.31", "2026.01.01", -1},

		// Month differs
		{"2026.05.01", "2026.04.30", 1},
		{"2026.03.31", "2026.04.01", -1},

		// Day differs
		{"2026.04.08", "2026.04.07", 1},
		{"2026.04.06", "2026.04.07", -1},

		// Patch releases
		{"2026.04.07", "2026.04.06", 1},
		{"2026.04.01", "2026.04.02", -1},

		// Release vs pre-release (release wins)
		{"2026.04.07", "2026.04.07-rc1", 1},
		{"2026.04.07-rc1", "2026.04.07", -1},

		// Pre-release ordering (lexicographic)
		{"2026.04.07-rc2", "2026.04.07-rc1", 1},
		{"2026.04.07-beta1", "2026.04.07-rc1", -1},

		// Dev sorts after everything
		{"dev", "2099.12.31", 1},
		{"2099.12.31", "dev", -1},
		{"dev", "dev", 0},

		// v prefix
		{"v2026.04.07", "2026.04.07", 0},

		// Two-part vs three-part
		{"2026.04.01", "2026.04", 1},
		{"2026.04", "2026.04.01", -1},

		// Invalid sorts before valid
		{"garbage", "2026.04.07", -1},
		{"2026.04.07", "garbage", 1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := Compare(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsNewer(t *testing.T) {
	if !IsNewer("2026.04.07", "2026.04.06") {
		t.Error("expected 2026.04.07 to be newer than 2026.04.06")
	}
	if IsNewer("2026.04.06", "2026.04.07") {
		t.Error("expected 2026.04.06 to NOT be newer than 2026.04.07")
	}
	if IsNewer("2026.04.07", "2026.04.07") {
		t.Error("expected equal versions to NOT be newer")
	}
}

func TestIsNewerOrEqual(t *testing.T) {
	if !IsNewerOrEqual("2026.04.07", "2026.04.07") {
		t.Error("expected equal versions to be newer-or-equal")
	}
	if !IsNewerOrEqual("2026.04.08", "2026.04.07") {
		t.Error("expected 2026.04.08 to be newer-or-equal to 2026.04.07")
	}
	if IsNewerOrEqual("2026.04.06", "2026.04.07") {
		t.Error("expected 2026.04.06 to NOT be newer-or-equal to 2026.04.07")
	}
}
