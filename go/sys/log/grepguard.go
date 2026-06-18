package log

import (
	"strconv"
	"strings"
)

// This file is ported VERBATIM from the agent's log-query handler (audit F-35).
// It is the structural ReDoS guard for grep patterns. Until the agent migrates
// onto this package the two copies coexist; keep them in sync, and prefer this
// one as the source of truth thereafter.

// isPathologicalGrepPattern flags regex shapes that are known to
// drive PCRE / RE2 into catastrophic backtracking (audit F-35).
// Returns a non-empty reason string when the pattern is rejected.
//
// The detector is intentionally conservative — it rejects on
// structural heuristics rather than trying to actually evaluate
// catastrophic-backtracking risk (which is undecidable in general).
// False positives are acceptable here: a rejected pattern returns a
// clean error to the caller; the worst-case is the operator has to
// rephrase a query. False negatives are not: a pathological pattern
// that slips through hangs `journalctl --grep` on the agent and
// denies log-query service.
//
// Rules (each independently disqualifying):
//   - nested quantifier on a group: `(...)*`, `(...)+`, `(...){n,}`
//     where the inner group contains its own quantifier (`*`, `+`,
//     `{n,}`). Classic `(a+)+`, `(a*)*`, `(a{1,})+` shapes.
//   - overlapping alternation under a quantifier: `(a|a)+`,
//     `(a|ab)+` — flagged by any `|` inside a quantified group.
//   - more than 5 unbounded quantifiers (`*`, `+`, `{n,}`) total —
//     compounds with the above rules to catch staircase patterns.
func isPathologicalGrepPattern(p string) string {
	// Count unbounded quantifiers — `*`, `+`, `{n,}`. `\` escapes
	// the following metachar so we skip a pair when we see one.
	unbounded := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' && i+1 < len(p) {
			i++
			continue
		}
		switch c {
		case '*', '+':
			unbounded++
		case '{':
			if quantifierUnbounded(p[i:]) {
				unbounded++
			}
		}
	}
	if unbounded > 5 {
		return "too many unbounded quantifiers (max 5)"
	}

	// Walk groups and look for nested-quantifier / alternation-
	// under-quantifier shapes.
	depth := 0
	type groupState struct {
		start         int
		hasAlt        bool
		hasInnerQuant bool
	}
	var stack []groupState
	for i := 0; i < len(p); i++ {
		c := p[i]
		// Skip escapes — `\(` and `\|` are literal characters, not
		// regex metas.
		if c == '\\' && i+1 < len(p) {
			i++
			continue
		}
		switch c {
		case '(':
			stack = append(stack, groupState{start: i})
			depth++
		case ')':
			if depth == 0 {
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			depth--
			// Propagate the closed group's quantifier/alternation state up to its
			// parent, so an outer quantifier still sees an unbounded quantifier or
			// alternation nested one level deeper — `((a+))+`, `((a|ab))+`,
			// `((.*a)){2}` would otherwise bypass the guard.
			if len(stack) > 0 {
				if top.hasInnerQuant {
					stack[len(stack)-1].hasInnerQuant = true
				}
				if top.hasAlt {
					stack[len(stack)-1].hasAlt = true
				}
			}
			// Is the closing paren followed by an unbounded quantifier?
			if i+1 < len(p) {
				next := p[i+1]
				if next == '*' || next == '+' || (next == '{' && quantifierUnbounded(p[i+1:])) {
					if top.hasInnerQuant {
						return "nested unbounded quantifier (catastrophic backtracking shape)"
					}
					if top.hasAlt {
						return "alternation under unbounded quantifier (catastrophic backtracking shape)"
					}
				}
				// Bounded `{n}`/`{n,m}` repetition of a group that itself
				// contains an unbounded quantifier is degree-N polynomial
				// backtracking — `(.*a){11}` is catastrophic even though `{11}`
				// is "bounded". The UPPER bound drives the worst case, so
				// `(.*a){1,11}` is just as bad as `(.*a){11}` (lo=1 is
				// irrelevant). Flag when the max repetition count is >= 2.
				// (Alternation under a BOUNDED repeat is fine — bounded
				// branching — so only hasInnerQuant qualifies here.)
				if next == '{' && top.hasInnerQuant {
					if _, hi, ok := boundedRepeatBounds(p[i+1:]); ok && hi >= 2 {
						return "bounded repetition of an unbounded group (catastrophic backtracking shape)"
					}
				}
			}
		case '|':
			if depth > 0 {
				stack[len(stack)-1].hasAlt = true
			}
		case '*', '+':
			if depth > 0 {
				stack[len(stack)-1].hasInnerQuant = true
			}
		case '{':
			if j := strings.IndexByte(p[i:], '}'); j > 0 && quantifierUnbounded(p[i:]) {
				if depth > 0 {
					stack[len(stack)-1].hasInnerQuant = true
				}
				i += j
			}
		}
	}
	return ""
}

// boundedRepeatBounds parses a BOUNDED `{n}` or `{n,m}` token starting at p[0]
// and returns (lo, hi, ok). For `{n}`, lo==hi==n. Returns ok=false for a
// non-quantifier, a malformed token, or an unbounded `{n,}` (those are handled
// by quantifierUnbounded). The HI bound is what drives worst-case backtracking
// when the repeated group contains an unbounded quantifier — `(...){1,1000}`
// can still try up to 1000 repetitions.
func boundedRepeatBounds(p string) (lo, hi int, ok bool) {
	if len(p) == 0 || p[0] != '{' {
		return 0, 0, false
	}
	j := strings.IndexByte(p, '}')
	if j <= 0 {
		return 0, 0, false
	}
	body := p[1:j]
	if strings.HasSuffix(body, ",") {
		return 0, 0, false // `{n,}` — unbounded
	}
	k := strings.IndexByte(body, ',')
	if k < 0 {
		// `{n}` — lo == hi == n
		n, err := strconv.Atoi(strings.TrimSpace(body))
		if err != nil {
			return 0, 0, false
		}
		return n, n, true
	}
	// `{n,m}` — lo = n, hi = m
	n, err := strconv.Atoi(strings.TrimSpace(body[:k]))
	if err != nil {
		return 0, 0, false
	}
	m, err := strconv.Atoi(strings.TrimSpace(body[k+1:]))
	if err != nil {
		return 0, 0, false
	}
	return n, m, true
}

// quantifierUnbounded reports whether a `{n,m?}` token starting at
// p[0] is unbounded — `{n,}` is unbounded; `{n}` and `{n,m}` are
// bounded.
func quantifierUnbounded(p string) bool {
	if len(p) == 0 || p[0] != '{' {
		return false
	}
	j := strings.IndexByte(p, '}')
	if j <= 0 {
		return false
	}
	body := p[1:j]
	if !strings.Contains(body, ",") {
		return false // `{n}` — bounded
	}
	parts := strings.SplitN(body, ",", 2)
	return len(parts) == 2 && parts[1] == "" // `{n,}` — unbounded
}
