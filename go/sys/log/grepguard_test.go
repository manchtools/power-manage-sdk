package log

import "testing"

func TestIsPathologicalGrepPattern(t *testing.T) {
	cases := []struct {
		name     string
		pat      string
		rejected bool
	}{
		{"empty", "", false},
		{"plain literal", "error: connection refused", false},
		{"simple quantifiers", "a+b*c?", false},
		{"group no inner quant", "(abc)+", false},
		{"bounded repeat of plain group", "(ab){5}", false},
		{"five unbounded ok", "a*b*c*d*e*", false},
		{"escaped parens are literal", `\(a+\)+`, false},
		{"bounded {1} of unbounded group ok", "(.*a){1}", false},
		{"unmatched close paren tolerated", "a)b", false},

		{"nested quant star", "(a*)*", true},
		{"nested quant plus", "(a+)+", true},
		{"nested quant unbounded brace", "(a{1,})+", true},
		{"alternation under quant", "(a|a)+", true},
		{"alternation under quant overlapping", "(a|ab)+", true},
		{"six unbounded too many", "a*b*c*d*e*f*", true},
		{"bounded repeat of unbounded group", "(.*a){11}", true},
		{"bounded range repeat of unbounded group", "(.*a){1,11}", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := isPathologicalGrepPattern(tc.pat)
			if tc.rejected && reason == "" {
				t.Errorf("isPathologicalGrepPattern(%q) accepted; want rejected", tc.pat)
			}
			if !tc.rejected && reason != "" {
				t.Errorf("isPathologicalGrepPattern(%q) rejected (%s); want accepted", tc.pat, reason)
			}
		})
	}
}

func TestBoundedRepeatBounds(t *testing.T) {
	cases := []struct {
		in     string
		lo, hi int
		ok     bool
	}{
		{"{5}", 5, 5, true},
		{"{1,11}", 1, 11, true},
		{"{1,}", 0, 0, false}, // unbounded
		{"{x}", 0, 0, false},
		{"{x,5}", 0, 0, false}, // bad low bound
		{"{1,x}", 0, 0, false}, // bad high bound
		{"x", 0, 0, false},
		{"{nodelim", 0, 0, false},
	}
	for _, tc := range cases {
		lo, hi, ok := boundedRepeatBounds(tc.in)
		if ok != tc.ok || (ok && (lo != tc.lo || hi != tc.hi)) {
			t.Errorf("boundedRepeatBounds(%q) = (%d,%d,%v), want (%d,%d,%v)", tc.in, lo, hi, ok, tc.lo, tc.hi, tc.ok)
		}
	}
}

func TestQuantifierUnbounded(t *testing.T) {
	cases := map[string]bool{
		"{1,}":     true,
		"{1,5}":    false,
		"{5}":      false,
		"x":        false,
		"{nodelim": false,
	}
	for in, want := range cases {
		if got := quantifierUnbounded(in); got != want {
			t.Errorf("quantifierUnbounded(%q) = %v, want %v", in, got, want)
		}
	}
}
