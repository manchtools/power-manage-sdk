package verify

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/cryptotest"
)

// TestEverySignatureDomainRoundTripsAndIsIsolated is the self-discovering
// completeness guard for the CA-signing domains (ADR-0007). The existing
// stream-RPC tests pin behaviour with HARDCODED domain arrays, which silently
// go stale: add a sixth `*SignatureDomain` constant and nothing forces it to be
// round-tripped or proven cross-isolated — the classic fails-open hardcoded
// list. This guard derives the domain set straight from the source, so every
// present AND future domain is covered automatically.
//
// For ALL signing domains it proves:
//   - the value is non-empty and UNIQUE — two surfaces sharing a domain string
//     would let a signature minted for one verify for the other (cross-surface
//     replay; verify.go's own comment says "never reuse an existing domain").
//   - sign->verify round-trips under its own domain, and a signature minted
//     under it is REJECTED under every other domain (isolation).
//
// NB: this guards the signing PRIMITIVE over the whole domain set. The
// per-surface WIRING (every stream domain is actually signed at the control
// server AND verified fail-closed at the agent) is covered by example tests in
// each repo (server stream_dispatch_signing_test.go, agent
// stream_rpc_verify_test.go); a fully self-discovering cross-repo wiring guard
// would need a shared exported domains slice + an sdk version-bump round-trip
// (tracked as G8b in INVARIANTS.md).
func TestEverySignatureDomainRoundTripsAndIsIsolated(t *testing.T) {
	domains := discoverSignatureDomains(t)
	if len(domains) < 2 {
		t.Fatalf("matches-zero guard: discovered %d signature domains, need >=2 to prove isolation — the detector is mis-scoped (did the *SignatureDomain consts move?)", len(domains))
	}

	// Distinct, non-empty values — a collision is a cross-surface replay hole.
	seen := map[string]string{} // value -> first const name
	values := make([]string, 0, len(domains))
	for name, val := range domains {
		if val == "" {
			t.Errorf("%s has an empty domain value — every signing surface must declare a distinct, non-empty domain", name)
			continue
		}
		if prev, dup := seen[val]; dup {
			t.Errorf("%s and %s share the domain string %q — a signature for one would verify for the other (cross-surface replay)", prev, name, val)
			continue
		}
		seen[val] = name
		values = append(values, val)
	}

	certPEM, key, _ := cryptotest.GenCA(t, "Test CA")
	signer := NewActionSigner(key)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	payload := []byte("canonical-payload-bytes")

	for _, d := range values {
		sig, err := signer.SignDomain(d, payload)
		if err != nil {
			t.Fatalf("SignDomain(%s): %v", d, err)
		}
		if err := verifier.VerifyDomain(d, payload, sig); err != nil {
			t.Errorf("VerifyDomain(%s) rejected its own valid signature: %v", d, err)
		}
		for _, other := range values {
			if other == d {
				continue
			}
			if err := verifier.VerifyDomain(other, payload, sig); err == nil {
				t.Errorf("signature minted under %q verified under %q — cross-surface replay possible", d, other)
			}
		}
	}
}

// discoverSignatureDomains parses every non-test .go file in this package and
// returns each `<Name>SignatureDomain = "..."` constant as name->value. Reading
// the source (not a hardcoded list, and not reflection — consts are not
// reflectable) is what makes the guard self-discovering.
func discoverSignatureDomains(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if !strings.HasSuffix(id.Name, "SignatureDomain") || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					val, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						t.Fatalf("unquote %s: %v", id.Name, uerr)
					}
					out[id.Name] = val
				}
			}
		}
	}
	return out
}
