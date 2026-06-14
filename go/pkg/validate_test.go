package pkg

import (
	"strings"
	"testing"
)

// TestValidatePackageName_Accepts pins the set of shapes we know
// real-world package managers use. Regressions that reject any of
// these break legitimate actions.
func TestValidatePackageName_Accepts(t *testing.T) {
	cases := []string{
		"nginx",
		"curl",
		"gcc-12",
		"libasound2t64",
		"libstdc++6",
		"firefox-esr",
		"linux-image-amd64",
		"libc6:i386",       // apt multiarch
		"libc6:amd64",      // apt multiarch
		"python3.11",       // dnf
		"base-devel",       // pacman
		"org.videolan.VLC", // flatpak reverse-DNS
		"org.videolan.VLC/x86_64/stable",
		"runtime/org.freedesktop.Platform/x86_64/23.08",
		"foo-1.2.3",
		"_notquite", // starts alphanum... actually "_" is not alphanum. Skip.
	}
	for _, name := range cases {
		if name == "_notquite" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			if err := ValidatePackageName(name); err != nil {
				t.Errorf("legitimate name rejected: %v", err)
			}
		})
	}
}

// TestValidatePackageName_RejectsOptionInjection is the core of the
// fix: every leading-dash / leading-equals input is a potential
// option-injection attack on the underlying package manager, and
// must be refused at the SDK boundary.
func TestValidatePackageName_RejectsOptionInjection(t *testing.T) {
	cases := []string{
		"",
		"-y",
		"--force",
		"=evil",
		" nginx",       // leading whitespace
		"nginx ",       // trailing whitespace — we refuse via character class
		"foo bar",      // embedded space — argv confusion
		"pkg;rm -rf /", // shell metachar
		"pkg|cat",
		"pkg&whoami",
		"`reboot`",
		"$(reboot)",
		"pkg\nmalicious",
		"pkg\x00",
		"pkg=1.2.3", // apt name=version goes via InstallOptions.Version
		"pkg*",      // glob
		"pkg?",
		"pkg>out",
		"pkg<in",
		"pkg'quote",
		"pkg\"quote",
		"pkg\\back",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidatePackageName(name)
			if err == nil {
				t.Errorf("expected rejection of %q", name)
				return
			}
			if !strings.Contains(err.Error(), "package name") {
				t.Errorf("error should name the field; got: %v", err)
			}
		})
	}
}

// TestValidatePackageName_LengthCap asserts the 256-character cap.
func TestValidatePackageName_LengthCap(t *testing.T) {
	ok := "a" + strings.Repeat("b", 255)
	if err := ValidatePackageName(ok); err != nil {
		t.Errorf("256-char name rejected: %v", err)
	}
	tooLong := "a" + strings.Repeat("b", 256)
	if err := ValidatePackageName(tooLong); err == nil {
		t.Errorf("257-char name accepted; expected rejection")
	}
}

// --- WS8 argv-hardening validators (sdk#88) ---------------------------------

// TestValidateRpmPackageName_Accepts pins the legitimate RPM %{NAME}
// shapes ValidateRpmPackageName must let through. The name comes from
// `rpm -qp --qf %{NAME}` on a downloaded .rpm, so a regression that
// rejects any of these breaks a real install/remove.
func TestValidateRpmPackageName_Accepts(t *testing.T) {
	cases := []string{
		"bash",
		"kernel-core",
		"libstdc++",      // RPM names carry '+'
		"python3.11",     // dotted version segment in the name
		"NetworkManager", // mixed case
		"2048-cli",       // digit-leading is allowed; first char is alphanumeric
		"glibc-langpack-en",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRpmPackageName(name); err != nil {
				t.Errorf("legitimate rpm name rejected: %v", err)
			}
		})
	}
}

// TestValidateRpmPackageName_RejectsOptionInjection sources every
// invalid case from intent — a crafted .rpm can set %{NAME} to
// anything, and a name that begins with '-'/'=' or carries a
// metacharacter is option/argv confusion against `rpm -q`/`rpm -e`.
func TestValidateRpmPackageName_RejectsOptionInjection(t *testing.T) {
	cases := []string{
		"",                               // ABSENT
		"-e",                             // leading dash → option to rpm
		"--eval=%{lua:os.execute('id')}", // rpm macro evaluation via option
		"=evil",                          // leading '='
		" bash",                          // leading space
		"bash ",                          // trailing space
		"foo bar",                        // embedded space → argv confusion
		"pkg;rm -rf /",                   // shell metachar
		"pkg|cat",
		"$(reboot)",
		"`reboot`",
		"pkg\nmalicious",               // newline
		"pkg\x00",                      // NUL
		"a" + strings.Repeat("b", 256), // length cap (257 chars)
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRpmPackageName(name); err == nil {
				t.Errorf("expected rejection of %q", name)
			}
		})
	}
}

// TestValidateRepoBaseURL_Accepts pins the legitimate dnf baseurl /
// zypper url / pacman server shapes — including the package-manager
// template variables that must survive validation.
func TestValidateRepoBaseURL_Accepts(t *testing.T) {
	cases := []string{
		"https://dnf.example.com/fedora/$releasever",
		"https://arch.example.com/os/$arch",
		"https://mirror.example.com/repo/$basearch/os",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := ValidateRepoBaseURL(u); err != nil {
				t.Errorf("legitimate base URL rejected: %v", err)
			}
		})
	}
}

// TestValidateRepoBaseURL_Rejects sources invalid cases from intent: a
// repository base URL fetches root-installed packages, so it MUST be
// https (no http/ftp/file), MUST be a real URL with a host, and MUST
// NOT be flag-shaped or carry control characters.
func TestValidateRepoBaseURL_Rejects(t *testing.T) {
	cases := []string{
		"",                   // ABSENT
		"http://mirror/repo", // plaintext http → MITM of root packages
		"ftp://x/repo",       // wrong scheme
		"file:///etc",        // local file masquerading as a repo
		"-o/tmp/x",           // flag-shaped, no scheme
		"https://a\nb",       // control char (config injection)
		"https://",           // no host
		"not-a-url",          // no scheme/host
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := ValidateRepoBaseURL(u); err == nil {
				t.Errorf("expected rejection of %q", u)
			}
		})
	}
}

// TestValidateGpgKeyRef_Accepts pins the exact allowed shapes for a
// dnf/zypper Gpgkey: an https URL, a file:// absolute path, or a bare
// absolute filesystem path. These are what `rpm --import` legitimately
// consumes.
func TestValidateGpgKeyRef_Accepts(t *testing.T) {
	cases := []string{
		"https://dnf.example.com/RPM-GPG-KEY",
		"file:///etc/pki/rpm-gpg/RPM-GPG-KEY-foo",
		"/etc/pki/rpm-gpg/RPM-GPG-KEY-foo",
	}
	for _, ref := range cases {
		t.Run(ref, func(t *testing.T) {
			if err := ValidateGpgKeyRef(ref); err != nil {
				t.Errorf("legitimate gpg key ref rejected: %v", err)
			}
		})
	}
}

// TestValidateGpgKeyRef_Rejects sources invalid cases from intent: a
// key ref must be https / file:// / absolute path — never a flag, never
// plaintext http (MITM of the trust anchor), never an rpm transport
// like ext::, never a relative or traversing path.
func TestValidateGpgKeyRef_Rejects(t *testing.T) {
	cases := []string{
		"",                        // ABSENT
		"-",                       // flag-shaped
		"--import=/etc/shadow",    // option injection into rpm --import
		"http://evil/key",         // plaintext http → MITM the key
		"ext::sh -c id",           // rpm "external" transport → command exec
		"relative/key",            // relative path
		"file://../../etc/passwd", // file:// with traversal
		"/etc/../etc/shadow",      // absolute path with traversal
		"https://a\nhttps://b",    // control char
	}
	for _, ref := range cases {
		t.Run(ref, func(t *testing.T) {
			if err := ValidateGpgKeyRef(ref); err == nil {
				t.Errorf("expected rejection of %q", ref)
			}
		})
	}
}

// TestValidateRemoteName_Accepts pins the flatpak remote-alias shapes
// (configured remote names like "flathub") that must pass.
func TestValidateRemoteName_Accepts(t *testing.T) {
	cases := []string{"flathub", "fedora", "gnome-nightly", "flathub-beta"}
	for _, n := range cases {
		t.Run(n, func(t *testing.T) {
			if err := ValidateRemoteName(n); err != nil {
				t.Errorf("legitimate remote name rejected: %v", err)
			}
		})
	}
}

// TestValidateRemoteName_Rejects sources invalid cases from intent: a
// flatpak remote name is an operand to `flatpak install`, so a
// flag-shaped or space/control-bearing value is argv confusion.
func TestValidateRemoteName_Rejects(t *testing.T) {
	cases := []string{
		"",            // ABSENT
		"--from=evil", // flag-shaped
		"-x",
		"a b",      // embedded space
		"re\nmote", // control char
		"a/b",      // path separator is not a remote alias
	}
	for _, n := range cases {
		t.Run(n, func(t *testing.T) {
			if err := ValidateRemoteName(n); err == nil {
				t.Errorf("expected rejection of %q", n)
			}
		})
	}
}
