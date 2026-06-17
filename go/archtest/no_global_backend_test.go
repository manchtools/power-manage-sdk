package archtest

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

// noGlobalBackendVarAllowlist enumerates package-level vars whose name looks
// like a global backend selector but are legitimately something else. It should
// stay EMPTY: the rework (Decision 1/2) replaced the process-global privilege
// backend with a Backend passed to New(...) and read back via Runner.Backend()
// on the injected instance, so no capability keeps backend selection in a
// package global. Entries here are stale-guarded by assertNoStale.
var noGlobalBackendVarAllowlist = map[string]string{}

// global-backend setter/getter API names: SetPrivilegeBackend,
// CurrentPrivilegeBackend, SetBackend, CurrentBackend, GetBackend, … — the
// legacy process-global escalation surface this rework removed.
var backendFuncRe = regexp.MustCompile(`^(Set|Get|Current)[A-Za-z0-9_]*Backend$`)

// package-level vars that store "the backend" globally (e.g. the deleted
// `var backend atomic.Int32`). Tightly anchored so it matches a global SELECTOR
// store, not unrelated identifiers that merely contain "backend".
var backendVarRe = regexp.MustCompile(`(?i)^(current|active|default|global|the)?backend$`)

// TestNoGlobalBackendState locks Decision 1/2: a capability's privilege/runtime
// backend is chosen by the consumer and passed to New(...) (and read via
// Runner.Backend() on the instance) — never selected through a process-global
// setter/getter or stored in a package-level global. This guard fails the build
// if a Set*/Get*/Current*Backend package function or a global backend var is
// reintroduced anywhere under go/sys or go/pkg.
//
// Instance methods named Backend() (e.g. Runner.Backend()) are intentionally
// allowed — they report an injected instance's backend, not a global. The guard
// inspects only top-level, receiver-less declarations.
func TestNoGlobalBackendState(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "gen/") || strings.HasPrefix(rel, "go/archtest/") {
			return false
		}
		return strings.HasPrefix(rel, "go/sys/") || strings.HasPrefix(rel, "go/pkg/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero capability Go files — detector is mis-scoped")
	}

	allow := newAllowlist(noGlobalBackendVarAllowlist)
	inspectedDecls := 0

	for _, gf := range files {
		for _, decl := range gf.ast.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					continue // methods (e.g. Runner.Backend()) report an instance, not a global
				}
				inspectedDecls++
				if backendFuncRe.MatchString(d.Name.Name) {
					t.Errorf("global backend selector func %s at %s:%d — Decision 1 forbids a process-global backend setter/getter. Pass the Backend to New(...) and read Runner.Backend() on the injected instance.",
						d.Name.Name, gf.rel, gf.line(d))
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue // enum values are CONST; only a mutable VAR is a global store
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range vs.Names {
						inspectedDecls++
						if !backendVarRe.MatchString(name.Name) {
							continue
						}
						key := gf.rel + " :: var " + name.Name
						if allow.exempt(key) {
							continue
						}
						t.Errorf("package-level backend var %q at %s:%d — a global backend store is the rejected SetPrivilegeBackend pattern. Hold the Backend on a constructed instance instead. If this is genuinely not a backend selector, add a justified, guarded entry to noGlobalBackendVarAllowlist.",
							name.Name, gf.rel, gf.line(name))
					}
				}
			}
		}
	}

	if inspectedDecls == 0 {
		t.Fatal("matches-zero guard: inspected zero top-level declarations — the AST walk is broken and the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}
