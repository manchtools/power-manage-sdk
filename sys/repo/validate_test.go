package repo

import (
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
)

// --- name validation -------------------------------------------------------

func TestValidate_Name(t *testing.T) {
	m, _, _ := newTestManager(t, pkg.Dnf)
	good := []string{"corp", "epel-9", "my.repo_1", "A0"}
	for _, n := range good {
		// A valid name with a valid config must pass.
		r := Repository{Name: n, Dnf: &DnfConfig{BaseURL: "https://h/r"}}
		if err := m.Validate(r); err != nil {
			t.Errorf("Validate(name=%q) = %v, want nil", n, err)
		}
	}
	bad := map[string]string{
		"empty":        "",
		"leading dot":  ".hidden",
		"leading dash": "-rf",
		"space":        "a b",
		"slash":        "a/b",
		"traversal":    "../etc",
		"newline":      "a\nb",
		"too long":     strings.Repeat("a", maxNameLen+1),
		"non-ascii":    "café",
		"shell meta":   "a;b",
	}
	for label, n := range bad {
		r := Repository{Name: n, Dnf: &DnfConfig{BaseURL: "https://h/r"}}
		if err := m.Validate(r); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Validate(%s=%q) = %v, want ErrInvalidName", label, n, err)
		}
	}
}

// Validate on a name-only Repository (the Remove shape) checks only the name.
func TestValidate_NameOnlyRepository(t *testing.T) {
	m, _, _ := newTestManager(t, pkg.Apt)
	if err := m.Validate(Repository{Name: "ok"}); err != nil {
		t.Errorf("Validate(name-only) = %v, want nil (no sub-config to check)", err)
	}
	if err := m.Validate(Repository{Name: "-rf"}); !errors.Is(err, ErrInvalidName) {
		t.Errorf("Validate(name-only bad) = %v, want ErrInvalidName", err)
	}
}

// --- apt field validation --------------------------------------------------

func TestValidate_Apt(t *testing.T) {
	m, _, _ := newTestManager(t, pkg.Apt)
	base := func() *AptConfig { return &AptConfig{URL: "https://packages.example.com/apt"} }

	// apt is intentionally exempt from the https requirement (trust = signed
	// Release), so BOTH http and https are accepted.
	for _, u := range []string{"http://old.example.com/apt", "https://packages.example.com/apt"} {
		if err := m.Validate(Repository{Name: "r", Apt: &AptConfig{URL: u}}); err != nil {
			t.Errorf("Validate(apt url %q) = %v, want nil", u, err)
		}
	}

	reject := map[string]*AptConfig{
		"missing url":    {URL: ""},
		"control in url": {URL: "https://h/a\nDeb-Src: x"},
		// A raw space splits the deb822 URIs field into a SECOND URI — the
		// injection the old control-only check let through.
		"space (second-URI injection)": {URL: "https://h/a https://evil/"},
		"tab in url":                   {URL: "https://h/a\tb"},
		"non-http scheme (ftp)":        {URL: "ftp://h/a"},
		"file scheme":                  {URL: "file:///etc/passwd"},
		"not a url (no scheme/host)":   {URL: "packages.example.com/apt"},
		"unparseable (bad host)":       {URL: "http://[oops"}, // url.Parse: missing ']'
		"no host":                      {URL: "https:///path"},
		"embedded credentials":         {URL: "https://user:pass@h/a"},
		"control in dist":              mut(base(), func(c *AptConfig) { c.Distribution = "bad\nline" }),
		"bad dist shape":               mut(base(), func(c *AptConfig) { c.Distribution = "-bad" }),
		"control in component":         mut(base(), func(c *AptConfig) { c.Components = []string{"main", "x\ny"} }),
		"bad component shape":          mut(base(), func(c *AptConfig) { c.Components = []string{"@bad"} }),
		"control in arch":              mut(base(), func(c *AptConfig) { c.Arch = "amd64\n" }),
		"bad arch shape":               mut(base(), func(c *AptConfig) { c.Arch = "AMD64" }), // arch is lowercase
	}
	for label, c := range reject {
		err := m.Validate(Repository{Name: "r", Apt: c})
		if err == nil || (!errors.Is(err, ErrInvalidConfig)) {
			t.Errorf("Validate(apt %s) = %v, want ErrInvalidConfig", label, err)
		}
	}

	// A fully populated valid apt config (incl. a multi-line key blob, which is
	// NOT control-char validated) passes.
	ok := &AptConfig{
		URL: "https://h/a", Distribution: "bookworm",
		Components: []string{"main", "contrib"}, Arch: "amd64",
		GPGKey: []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END-----\n"),
	}
	if err := m.Validate(Repository{Name: "r", Apt: ok}); err != nil {
		t.Errorf("Validate(valid apt) = %v, want nil", err)
	}
}

// --- dnf field validation --------------------------------------------------

func TestValidate_Dnf(t *testing.T) {
	m, _, _ := newTestManager(t, pkg.Dnf)
	reject := map[string]*DnfConfig{
		"missing baseurl":    {BaseURL: ""},
		"http baseurl":       {BaseURL: "http://h/r"}, // dnf requires https
		"ftp baseurl":        {BaseURL: "ftp://h/r"},
		"control in baseurl": {BaseURL: "https://h/r\nrm -rf"},
		"control in desc":    {BaseURL: "https://h/r", Description: "x\ny"},
		"http gpgkey":        {BaseURL: "https://h/r", GPGKey: "http://h/key"},
		"flag gpgkey":        {BaseURL: "https://h/r", GPGKey: "-x"},
		"traversal gpgkey":   {BaseURL: "https://h/r", GPGKey: "/etc/../key"},
	}
	for label, c := range reject {
		if err := m.Validate(Repository{Name: "r", Dnf: c}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Validate(dnf %s) = %v, want ErrInvalidConfig", label, err)
		}
	}
	ok := &DnfConfig{BaseURL: "https://h/r", GPGKey: "https://h/RPM-GPG-KEY", Description: "Corp", Enabled: true, GPGCheck: true}
	if err := m.Validate(Repository{Name: "r", Dnf: ok}); err != nil {
		t.Errorf("Validate(valid dnf) = %v, want nil", err)
	}
	// A file:// gpgkey absolute path is accepted.
	if err := m.Validate(Repository{Name: "r", Dnf: &DnfConfig{BaseURL: "https://h/r", GPGKey: "/etc/pki/rpm-gpg/KEY"}}); err != nil {
		t.Errorf("Validate(dnf abs-path gpgkey) = %v, want nil", err)
	}
}

// --- pacman field validation -----------------------------------------------

func TestValidate_Pacman(t *testing.T) {
	m, _, _ := newTestManager(t, pkg.Pacman)
	reject := map[string]*PacmanConfig{
		"missing server":   {Server: ""},
		"http server":      {Server: "http://h/r"},
		"control server":   {Server: "https://h/r\nx"},
		"control siglevel": {Server: "https://h/r", SigLevel: "Optional\nTrustAll"},
		"bad siglevel":     {Server: "https://h/r", SigLevel: "Optional;rm"},
	}
	for label, c := range reject {
		if err := m.Validate(Repository{Name: "r", Pacman: c}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Validate(pacman %s) = %v, want ErrInvalidConfig", label, err)
		}
	}
	if err := m.Validate(Repository{Name: "r", Pacman: &PacmanConfig{Server: "https://h/$repo/$arch", SigLevel: "Optional TrustAll"}}); err != nil {
		t.Errorf("Validate(valid pacman) = %v, want nil", err)
	}
}

// --- zypper field validation -----------------------------------------------

func TestValidate_Zypper(t *testing.T) {
	m, _, _ := newTestManager(t, pkg.Zypper)
	reject := map[string]*ZypperConfig{
		"missing url":  {URL: ""},
		"http url":     {URL: "http://h/r"},
		"control url":  {URL: "https://h/r\nx"},
		"control desc": {URL: "https://h/r", Description: "a\nb"},
		"control type": {URL: "https://h/r", Type: "rpm\nmd"},
		"bad type":     {URL: "https://h/r", Type: "rpm md"},
		"http gpgkey":  {URL: "https://h/r", GPGKey: "http://h/k"},
		"flag gpgkey":  {URL: "https://h/r", GPGKey: "--import-me"},
	}
	for label, c := range reject {
		if err := m.Validate(Repository{Name: "r", Zypper: c}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Validate(zypper %s) = %v, want ErrInvalidConfig", label, err)
		}
	}
	ok := &ZypperConfig{URL: "https://h/r", Description: "Corp Repo", Type: "rpm-md", Enabled: true, Autorefresh: true, GPGKey: "https://h/KEY"}
	if err := m.Validate(Repository{Name: "r", Zypper: ok}); err != nil {
		t.Errorf("Validate(valid zypper) = %v, want nil", err)
	}
}

// mut clones-by-mutation: applies f to c and returns it (test sugar).
func mut(c *AptConfig, f func(*AptConfig)) *AptConfig { f(c); return c }
