// Package archtest holds architectural fitness functions for the SDK:
// self-discovering, module-wide invariant tests that fail the build when
// a known code smell is reintroduced or a good pattern is broken.
//
// # Scope for the SDK
//
// The SDK is a library (proto-generated code, crypto/signing helpers,
// package-manager exec abstraction). The guard that matters most here is
// the constant-time secret-comparison lock, because sdk/go/verify and
// sdk/go/crypto are the action-signing and encryption boundary.
//
// Guards from the server archtest suite that do NOT apply to the SDK and
// are intentionally absent:
//
//   - No-dynamic-SQL / projection-write: the SDK has no database.
//   - Unabstracted-clock: the SDK has no time-DECISION logic. Its only
//     time.Now() uses are external-command duration measurement in
//     sdk/go/pkg (intrinsically real wall-clock — injecting a fake clock
//     is meaningless there) and ULID timestamp seeding. Neither is a
//     testability-relevant decision, so a clock seam buys nothing.
//
// Standard library only (go/parser, go/ast, go/token, go/printer) — no
// golang.org/x/tools dependency. Every guard walks the module tree,
// asserts it inspected a non-empty set (cannot pass vacuously), and ships
// a no-stale-entry-guarded allowlist for true exceptions.
package archtest

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goFile is a parsed Go source file with its module-relative path.
type goFile struct {
	rel  string
	fset *token.FileSet
	ast  *ast.File
}

// moduleRoot walks up from the test's working directory to the directory
// containing go.mod (the SDK module root).
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}

// walkGoFiles parses every .go file under root whose module-relative,
// slash-separated path satisfies keep. Test files and vendor/testdata/.git
// are always skipped; keep narrows further (callers exclude generated and
// the archtest package itself).
func walkGoFiles(t *testing.T, root string, keep func(rel string) bool) []*goFile {
	t.Helper()
	var out []*goFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") || !keep(rel) {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", rel, perr)
		}
		out = append(out, &goFile{rel: rel, fset: fset, ast: f})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func (gf *goFile) line(n ast.Node) int { return gf.fset.Position(n.Pos()).Line }

// render returns the gofmt-style source of an AST node, whitespace
// collapsed, for stable allowlist keys and readable messages.
func render(fset *token.FileSet, n ast.Node) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, n); err != nil {
		return "<unprintable node>"
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// allowlist couples intentionally-exempt sites with their justifications
// and fails the build for any entry that no longer matches a site.
type allowlist struct {
	reason map[string]string
	used   map[string]bool
}

func newAllowlist(reasons map[string]string) *allowlist {
	return &allowlist{reason: reasons, used: make(map[string]bool)}
}

func (a *allowlist) exempt(key string) bool {
	if _, ok := a.reason[key]; ok {
		a.used[key] = true
		return true
	}
	return false
}

func (a *allowlist) assertNoStale(t *testing.T) {
	t.Helper()
	for key := range a.reason {
		if !a.used[key] {
			t.Errorf("stale allowlist entry never matched any site (remove it or fix the key): %q", key)
		}
	}
}
