package archtest

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// runnerRequiredAllowlist enumerates capability constructors that legitimately
// reject a nil exec.Runner WITHOUT the shared exec.ErrRunnerRequired sentinel.
// It should stay EMPTY: nil-runner rejection is identical everywhere, so every
// capability funnels it through the one generic sentinel and callers can match
// it with errors.Is regardless of which capability they built. Entries are keyed
// by "<rel>:<funcName>" and stale-guarded by assertNoStale.
var runnerRequiredAllowlist = map[string]string{}

// TestNilRunnerUsesSharedSentinel locks the rule that EVERY capability
// constructor taking an exec.Runner rejects a nil runner with the single shared
// exec.ErrRunnerRequired sentinel — never an ad-hoc errors.New / fmt.Errorf
// string. This is what makes the rejection errors.Is-matchable and uniform.
//
// It is self-discovering: it finds every function under go/sys and go/pkg that
// takes an exec.Runner parameter and guards it with `<param> == nil`, then
// requires that guard's body to reference exec.ErrRunnerRequired. A NEW
// capability that hand-rolls its own "runner is required" error fails the build.
// The companion guard (no per-package runner-required sentinel survives) and the
// per-package New(_, nil) unit tests (errors.Is at runtime) complete the pin.
func TestNilRunnerUsesSharedSentinel(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "gen/") || strings.HasPrefix(rel, "go/archtest/") {
			return false
		}
		// The exec package DEFINES the sentinel and constructs Runners rather
		// than consuming one, so it has no nil-runner constructor guard to check.
		if strings.HasPrefix(rel, "go/sys/exec/") {
			return false
		}
		return strings.HasPrefix(rel, "go/sys/") || strings.HasPrefix(rel, "go/pkg/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero capability Go files — detector is mis-scoped")
	}

	allow := newAllowlist(runnerRequiredAllowlist)
	guards := 0

	for _, gf := range files {
		execName := sdkExecLocalName(gf)
		if execName == "" {
			continue // this file does not import the SDK exec package, so no exec.Runner param
		}
		for _, decl := range gf.ast.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			params := runnerParamNames(fn, execName)
			if len(params) == 0 {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ifs, ok := n.(*ast.IfStmt)
				if !ok || !isNilCheckOn(ifs.Cond, params) {
					return true
				}
				guards++
				if blockReferences(ifs.Body, "ErrRunnerRequired") {
					return true
				}
				if allow.exempt(gf.rel + ":" + fn.Name.Name) {
					return true
				}
				t.Errorf("%s:%d: %s rejects a nil runner without the shared %s.ErrRunnerRequired sentinel — "+
					"return it (wrapped, e.g. fmt.Errorf(\"%s: %%w\", %s.ErrRunnerRequired)) so callers can errors.Is",
					gf.rel, gf.line(ifs), fn.Name.Name, execName, gf.ast.Name.Name, execName)
				return true
			})
		}
	}

	if guards == 0 {
		t.Fatal("matches-zero guard: found no `runner == nil` constructor guard at all — the detector is broken")
	}
	allow.assertNoStale(t)
}

// TestNoPerPackageRunnerRequiredSentinel forbids a package from declaring its own
// Err*RunnerRequired / "runner is required" sentinel: the generic one in exec is
// the single source so "everything uses our generic error". A duplicate would let
// two distinct sentinels drift apart and break uniform errors.Is matching.
func TestNoPerPackageRunnerRequiredSentinel(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "gen/") || strings.HasPrefix(rel, "go/archtest/") {
			return false
		}
		if strings.HasPrefix(rel, "go/sys/exec/") {
			return false // the one legitimate home of the shared sentinel
		}
		return strings.HasPrefix(rel, "go/sys/") || strings.HasPrefix(rel, "go/pkg/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero capability Go files — detector is mis-scoped")
	}

	inspected := 0
	for _, gf := range files {
		for _, decl := range gf.ast.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					inspected++
					// A var named like a runner-required error...
					if !strings.Contains(strings.ToLower(name.Name), "runnerrequired") {
						// ...or one whose errors.New/fmt.Errorf literal says so.
						if i < len(vs.Values) && constructsRunnerRequired(vs.Values[i]) {
							t.Errorf("%s:%d: %s constructs a 'runner is required' error — use the shared exec.ErrRunnerRequired instead of a per-package sentinel",
								gf.rel, gf.line(name), name.Name)
						}
						continue
					}
					t.Errorf("%s:%d: package-level %s — there must be only ONE runner-required sentinel (exec.ErrRunnerRequired); drop this per-package one",
						gf.rel, gf.line(name), name.Name)
				}
			}
		}
	}
	if inspected == 0 {
		t.Fatal("matches-zero guard: inspected no package-level vars — detector is broken")
	}
}

// sdkExecLocalName returns the local name the SDK exec package is imported under
// in gf (its alias, or "exec" by default), or "" if gf does not import it.
func sdkExecLocalName(gf *goFile) string {
	for _, imp := range gf.ast.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !strings.HasSuffix(path, "/sys/exec") {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return "exec"
	}
	return ""
}

// runnerParamNames returns the parameter names of fn whose type is
// <execName>.Runner (the injected SDK runner).
func runnerParamNames(fn *ast.FuncDecl, execName string) []string {
	var names []string
	if fn.Type.Params == nil {
		return names
	}
	for _, field := range fn.Type.Params.List {
		sel, ok := field.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Runner" {
			continue
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != execName {
			continue
		}
		for _, id := range field.Names {
			names = append(names, id.Name)
		}
	}
	return names
}

// isNilCheckOn reports whether cond is `<p> == nil` for one of params.
func isNilCheckOn(cond ast.Expr, params []string) bool {
	be, ok := cond.(*ast.BinaryExpr)
	if !ok || be.Op != token.EQL {
		return false
	}
	var ident *ast.Ident
	switch {
	case isNilIdent(be.Y):
		ident, _ = be.X.(*ast.Ident)
	case isNilIdent(be.X):
		ident, _ = be.Y.(*ast.Ident)
	}
	if ident == nil {
		return false
	}
	for _, p := range params {
		if p == ident.Name {
			return true
		}
	}
	return false
}

func isNilIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

// blockReferences reports whether any identifier named want appears anywhere in
// block (covers both a bare ErrRunnerRequired and the Sel of exec.ErrRunnerRequired).
func blockReferences(block *ast.BlockStmt, want string) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == want {
			found = true
			return false
		}
		return true
	})
	return found
}

// constructsRunnerRequired reports whether expr is an errors.New / fmt.Errorf
// call whose first string-literal argument mentions "runner is required".
func constructsRunnerRequired(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	return strings.Contains(strings.ToLower(lit.Value), "runner is required")
}
