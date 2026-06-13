package pkg

import (
	"slices"
	"strings"
	"testing"
)

// Threat model: AddRemote/RemoveRemote take an operator-supplied remote
// name and URL that reach `flatpak remote-add/-delete` argv. flatpak
// accepts behaviour-altering flags (--gpg-import=FILE, --no-gpg-verify,
// --from), so a name or URL beginning with "-" (or a non-repo URL scheme)
// must be refused, and the positionals must sit behind a "--".

func TestValidateRemoteName(t *testing.T) {
	for _, ok := range []string{"flathub", "gnome-nightly", "my.repo_1"} {
		if err := ValidateRemoteName(ok); err != nil {
			t.Errorf("ValidateRemoteName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"",                      // empty
		"-flathub",              // flag shape
		"--no-gpg-verify",       // flag shape
		"has space",             // whitespace
		"name\ninjected",        // control char
		"slash/name",            // path separator
		strings.Repeat("a", 65), // over length cap
	} {
		if err := ValidateRemoteName(bad); err == nil {
			t.Errorf("ValidateRemoteName(%q) = nil, want error", bad)
		}
	}
}

func TestValidateRemoteURL(t *testing.T) {
	for _, ok := range []string{
		"https://flathub.org/repo/flathub.flatpakrepo",
		"oci+https://registry.example.com/repo",
		"http://mirror.internal/repo",
	} {
		if err := ValidateRemoteURL(ok); err != nil {
			t.Errorf("ValidateRemoteURL(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"",                   // empty
		"--from",             // flag shape, no scheme
		"-x",                 // flag shape
		"file:///etc/passwd", // non-repo scheme
		"ext::sh -c evil",    // transport injection shape
		"https://h\nost/x",   // control char
		"not-a-url",          // no scheme
	} {
		if err := ValidateRemoteURL(bad); err == nil {
			t.Errorf("ValidateRemoteURL(%q) = nil, want error", bad)
		}
	}
}

func TestFlatpakRemoteAddArgs_ValidatesAndSeparates(t *testing.T) {
	args, err := flatpakRemoteAddArgs("flathub", "https://flathub.org/repo/flathub.flatpakrepo", true)
	if err != nil {
		t.Fatalf("flatpakRemoteAddArgs = %v, want nil", err)
	}
	// remote-add and option flags precede "--"; name + url follow it.
	i := slices.Index(args, "--")
	if i < 0 {
		t.Fatalf("no end-of-options marker in %v", args)
	}
	if args[0] != "remote-add" {
		t.Errorf("argv[0] = %q, want remote-add", args[0])
	}
	if got := args[i+1:]; !slices.Equal(got, []string{"flathub", "https://flathub.org/repo/flathub.flatpakrepo"}) {
		t.Errorf("positionals = %v, want [flathub <url>]", got)
	}
	if !slices.Contains(args, "--system") {
		t.Errorf("useSudo=true must add --system: %v", args)
	}

	// Invalid input is rejected before any argv is built.
	if _, err := flatpakRemoteAddArgs("-evil", "https://x/y", false); err == nil {
		t.Error("flatpakRemoteAddArgs accepted flag-shaped name")
	}
	if _, err := flatpakRemoteAddArgs("ok", "file:///etc/passwd", false); err == nil {
		t.Error("flatpakRemoteAddArgs accepted file:// url")
	}
}

func TestFlatpakRemoteDeleteArgs_ValidatesAndSeparates(t *testing.T) {
	args, err := flatpakRemoteDeleteArgs("flathub", false)
	if err != nil {
		t.Fatalf("flatpakRemoteDeleteArgs = %v, want nil", err)
	}
	i := slices.Index(args, "--")
	if i < 0 || !slices.Equal(args[i+1:], []string{"flathub"}) {
		t.Errorf("delete argv = %v, want name behind --", args)
	}
	if !slices.Contains(args, "--user") {
		t.Errorf("useSudo=false must add --user: %v", args)
	}
	if _, err := flatpakRemoteDeleteArgs("--force", false); err == nil {
		t.Error("flatpakRemoteDeleteArgs accepted flag-shaped name")
	}
}
