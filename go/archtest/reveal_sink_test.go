package archtest

import (
	"go/ast"
	"strings"
	"testing"
)

// revealSinkAllowlist lists the ONLY call sites permitted to call
// exec.Secret.Reveal() — the sanctioned credential sinks that must hand the
// plaintext to an OS tool. Keyed by "<module-rel path> :: <rendered call>".
// assertNoStale fails the build if a listed sink stops calling Reveal (e.g. it
// was refactored away), so the allowlist cannot rot into a silent gap.
var revealSinkAllowlist = map[string]string{
	"go/sys/user/password.go :: password.Reveal()": "chpasswd stdin: the sole sink that writes a user password to useradd's helper",
	"go/sys/encryption/luks.go :: key.Reveal()":    "LUKS key file in /dev/shm: cryptsetup --key-file sink (never argv)",
	"go/sys/encryption/tpm.go :: key.Reveal()":     "systemd-cryptenroll stdin: the TPM-enrollment passphrase sink (never argv)",
}

// TestRevealOnlyFromKnownSinks locks the exec.Secret redaction contract: the
// plaintext may be obtained via Reveal() ONLY at the enumerated credential
// sinks (chpasswd stdin today; the wifi PSK keyfile, LUKS stdin, etc. as those
// capability PRs land). Any other .Reveal() call — e.g. one slipped into a
// slog/fmt path — fails the build. This is the architecture-level complement to
// the per-package unit pin that a Secret never appears in a recorded
// Command.Args.
func TestRevealOnlyFromKnownSinks(t *testing.T) {
	root := moduleRoot(t)
	// Scan the device-side capability surface + pkg, where Secrets live. Skip
	// generated code, the exec package itself (which DEFINES Reveal), and
	// archtest.
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "gen/") || strings.HasPrefix(rel, "go/archtest/") {
			return false
		}
		if rel == "go/sys/exec/secret.go" {
			return false // the definition of Reveal, not a use
		}
		return strings.HasPrefix(rel, "go/sys/") || strings.HasPrefix(rel, "go/pkg/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero capability Go files — detector is mis-scoped")
	}

	allow := newAllowlist(revealSinkAllowlist)
	sawReveal := false

	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Reveal" || len(call.Args) != 0 {
				return true
			}
			sawReveal = true
			key := gf.rel + " :: " + render(gf.fset, call)
			if allow.exempt(key) {
				return true
			}
			t.Errorf("unsanctioned Secret.Reveal() at %s:%d — %s\n  Reveal() exposes credential plaintext and must appear only at an enumerated OS sink. If this is a real new sink, add a justified, guarded entry to revealSinkAllowlist; otherwise pass the Secret itself (it redacts in logs/format).",
				gf.rel, gf.line(call), render(gf.fset, call))
			return true
		})
	}

	if !sawReveal {
		t.Fatal("matches-zero guard: found no Reveal() calls anywhere — the detector is dead (or every sink was removed); the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}
