package archtest

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// secretCompareAllowlist lists comparisons that match the secret-name
// heuristic but are not timing-sensitive secret-value compares. Each entry
// is justified; assertNoStale fails the build if one stops matching.
// Keyed by "<module-rel path> :: <rendered expression>".
var secretCompareAllowlist = map[string]string{}

// TestSecretComparesAreConstantTime forbids comparing secret material
// (tokens, MACs, signatures, fingerprints, password/digest bytes) with
// == / != / bytes.Equal in the SDK — the action-signing and encryption
// boundary (sdk/go/verify, sdk/go/crypto). The correct primitives are
// subtle.ConstantTimeCompare and hmac.Equal. Presence checks and metadata
// fields are excluded.
func TestSecretComparesAreConstantTime(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		// Skip generated proto code and the archtest package itself.
		return !strings.HasPrefix(rel, "gen/") && !strings.HasPrefix(rel, "archtest/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero SDK Go files — detector is mis-scoped")
	}

	allow := newAllowlist(secretCompareAllowlist)
	sawComparison := false
	sawSecretName := false

	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if x.Op == token.EQL || x.Op == token.NEQ {
					sawComparison = true
					checkSecretCompare(t, gf, x, x.X, x.Y, allow, &sawSecretName)
				}
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "bytes" && sel.Sel.Name == "Equal" && len(x.Args) == 2 {
						sawComparison = true
						checkSecretCompare(t, gf, x, x.Args[0], x.Args[1], allow, &sawSecretName)
					}
				}
			}
			return true
		})
	}

	if !sawComparison {
		t.Fatal("matches-zero guard: found no equality comparisons — the AST walk is not reaching real code")
	}
	if !sawSecretName {
		t.Fatal("matches-zero guard: the secret-name detector matched no identifier anywhere — the regex/scoping is dead, the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

func checkSecretCompare(t *testing.T, gf *goFile, node ast.Node, lhs, rhs ast.Expr, allow *allowlist, sawSecretName *bool) {
	t.Helper()
	lSecret := looksLikeSecretOperand(lhs)
	rSecret := looksLikeSecretOperand(rhs)
	if lSecret || rSecret {
		*sawSecretName = true
	}
	if !lSecret && !rSecret {
		return
	}
	if isPresenceComparand(lhs) || isPresenceComparand(rhs) {
		return
	}
	key := gf.rel + " :: " + render(gf.fset, node)
	if allow.exempt(key) {
		return
	}
	t.Errorf("non-constant-time secret compare at %s:%d — %s\n  compares secret material with ==/!=/bytes.Equal, which leaks length and content via timing. Use subtle.ConstantTimeCompare or hmac.Equal. If this is metadata (not secret bytes), add a justified, guarded entry to secretCompareAllowlist.",
		gf.rel, gf.line(node), render(gf.fset, node))
}
