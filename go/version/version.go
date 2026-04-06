// Package version provides comparison utilities for Power Manage version strings.
//
// Version format: "YYYY.MM.DD" (e.g. "2026.04.07"), optionally with a suffix
// like "-rc1" or "-beta2". The special version "dev" sorts after all releases.
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Parts holds the parsed components of a version string.
type Parts struct {
	Year   int
	Month  int
	Day    int
	Suffix string // e.g. "rc1", "beta2", "" for release
}

// Parse extracts components from a version string.
// Accepts: "2026.04.07", "2026.04.07-rc1", "2026.4", "dev".
func Parse(v string) (Parts, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return Parts{}, fmt.Errorf("empty version string")
	}
	if v == "dev" {
		return Parts{Year: 9999, Month: 99, Day: 99, Suffix: "dev"}, nil
	}

	// Strip prefix "v" if present
	v = strings.TrimPrefix(v, "v")

	// Split suffix on "-"
	var suffix string
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		suffix = v[idx+1:]
		if suffix == "" {
			return Parts{}, fmt.Errorf("invalid version %q: trailing '-' with no suffix", v)
		}
		v = v[:idx]
	}

	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return Parts{}, fmt.Errorf("invalid version format %q: expected YYYY.MM or YYYY.MM.DD", v)
	}

	year, err := strconv.Atoi(parts[0])
	if err != nil {
		return Parts{}, fmt.Errorf("invalid year %q: %w", parts[0], err)
	}
	if year < 1 || year > 9999 {
		return Parts{}, fmt.Errorf("invalid year %d: out of range [1-9999]", year)
	}

	month, err := strconv.Atoi(parts[1])
	if err != nil {
		return Parts{}, fmt.Errorf("invalid month %q: %w", parts[1], err)
	}
	if month < 1 || month > 12 {
		return Parts{}, fmt.Errorf("invalid month %d: out of range [1-12]", month)
	}

	day := 0
	if len(parts) == 3 {
		day, err = strconv.Atoi(parts[2])
		if err != nil {
			return Parts{}, fmt.Errorf("invalid day %q: %w", parts[2], err)
		}
		if day < 1 || day > 31 {
			return Parts{}, fmt.Errorf("invalid day %d: out of range [1-31]", day)
		}
	}

	return Parts{Year: year, Month: month, Day: day, Suffix: suffix}, nil
}

// Compare returns -1 if a < b, 0 if a == b, 1 if a > b.
// Unparseable versions sort before valid ones.
// Release versions sort after pre-release (rc/beta) versions of the same number.
func Compare(a, b string) int {
	pa, errA := Parse(a)
	pb, errB := Parse(b)

	// Unparseable sorts before valid
	if errA != nil && errB != nil {
		return strings.Compare(a, b)
	}
	if errA != nil {
		return -1
	}
	if errB != nil {
		return 1
	}

	// Compare year.month.day
	if pa.Year != pb.Year {
		return cmpInt(pa.Year, pb.Year)
	}
	if pa.Month != pb.Month {
		return cmpInt(pa.Month, pb.Month)
	}
	if pa.Day != pb.Day {
		return cmpInt(pa.Day, pb.Day)
	}

	// Same version number — release ("") sorts after pre-release ("rc1")
	if pa.Suffix == pb.Suffix {
		return 0
	}
	if pa.Suffix == "" {
		return 1 // a is release, b is pre-release
	}
	if pb.Suffix == "" {
		return -1 // a is pre-release, b is release
	}
	return compareSuffix(pa.Suffix, pb.Suffix)
}

// IsNewer returns true if a is strictly newer than b.
func IsNewer(a, b string) bool {
	return Compare(a, b) > 0
}

// IsNewerOrEqual returns true if a is newer than or equal to b.
func IsNewerOrEqual(a, b string) bool {
	return Compare(a, b) >= 0
}

// compareSuffix compares pre-release suffixes numerically.
// Splits each into alpha prefix + numeric tail (e.g. "rc10" → "rc", 10).
// Alpha prefixes are compared lexicographically, then numeric tails as integers.
func compareSuffix(a, b string) int {
	aPre, aNum := splitSuffix(a)
	bPre, bNum := splitSuffix(b)
	if aPre != bPre {
		return strings.Compare(aPre, bPre)
	}
	return cmpInt(aNum, bNum)
}

// splitSuffix splits a suffix like "rc10" into ("rc", 10).
// If there's no numeric tail, returns (suffix, 0).
func splitSuffix(s string) (string, int) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) {
		return s, 0
	}
	n, _ := strconv.Atoi(s[i:])
	return s[:i], n
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
