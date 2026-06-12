package archtest

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// identName returns the most specific name an expression is known by: the
// identifier, or the trailing selector field (foo.Bar -> "Bar").
func identName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.StarExpr:
		return identName(x.X)
	case *ast.ParenExpr:
		return identName(x.X)
	}
	return ""
}

// isPresenceComparand reports whether an operand is a nil / empty-string /
// zero literal — i.e. the comparison is a presence check, not a
// secret-value comparison.
func isPresenceComparand(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "nil"
	case *ast.BasicLit:
		switch x.Kind {
		case token.STRING:
			if s, err := strconv.Unquote(x.Value); err == nil {
				return s == ""
			}
		case token.INT, token.FLOAT:
			return x.Value == "0" || x.Value == "0.0"
		}
	case *ast.CallExpr:
		if len(x.Args) == 1 {
			return isPresenceComparand(x.Args[0])
		}
	}
	return false
}

// secretNameRe matches identifiers that hold secret material. The full
// "signature"/"hmac" forms are used (bare "sig"/"mac" collide with
// "assign"/"format"). A match is a violation only when it is not metadata
// (secretMetaSuffixes) and not a presence check.
var secretNameRe = regexp.MustCompile(`(?i)(token|secret|hmac|signature|fingerprint|password|passwd|digest|apikey)`)

// secretMetaSuffixes name fields that describe a secret rather than carry
// its bytes (TokenType, KeyID, SignatureSize, ...).
var secretMetaSuffixes = []string{
	"type", "kind", "id", "name", "len", "length", "count", "version",
	"expiry", "expiresat", "at", "format", "algorithm", "algo", "method",
	"status", "enabled", "disabled", "index", "idx", "field", "size",
}

// looksLikeSecretOperand reports whether an operand names secret material
// that must be compared in constant time.
func looksLikeSecretOperand(e ast.Expr) bool {
	name := identName(e)
	if name == "" || !secretNameRe.MatchString(name) {
		return false
	}
	lower := strings.ToLower(name)
	for _, suf := range secretMetaSuffixes {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	return true
}
