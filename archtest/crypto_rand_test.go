package archtest

import (
	"go/ast"
	"strings"
	"testing"
)

// TestCryptoRandReadErrorsAreChecked locks the entropy boundary: any direct
// crypto/rand.Read call must inspect its error. If entropy acquisition fails and
// code silently proceeds with a zero/partial buffer, attacker-controlled names,
// nonces, or keys can become predictable. Helpers that need randomness should
// return the error or use APIs that already do.
func TestCryptoRandReadErrorsAreChecked(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "gen/") || strings.HasPrefix(rel, "archtest/") {
			return false
		}
		return true
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero Go files")
	}

	checkedImports := 0
	for _, gf := range files {
		randName := importLocalName(gf, "crypto/rand")
		if randName == "" {
			continue
		}
		checkedImports++
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				if call := randReadCall(n, randName); call != nil {
					t.Errorf("%s:%d: crypto/rand.Read result is not assigned; check and propagate the error", gf.rel, gf.line(call))
				}
				return true
			}
			for i, rhs := range assign.Rhs {
				call := randReadCall(rhs, randName)
				if call == nil {
					continue
				}
				if len(assign.Lhs) <= i+1 || isBlankIdent(assign.Lhs[i+1]) {
					t.Errorf("%s:%d: crypto/rand.Read error is discarded; handle it fail-closed", gf.rel, gf.line(call))
				}
			}
			return false
		})
	}
	if checkedImports == 0 {
		t.Fatal("matches-zero guard: no crypto/rand imports found")
	}
}

func randReadCall(n ast.Node, randName string) *ast.CallExpr {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Read" {
		return nil
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != randName {
		return nil
	}
	return call
}

func isBlankIdent(expr ast.Expr) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "_"
}
