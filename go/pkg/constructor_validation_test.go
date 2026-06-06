package pkg

import (
	"strings"
	"testing"
)

// These tests pin SDK audit finding #7 — direct callers of the
// per-backend constructors (NewApt / NewDnf / NewPacman / NewZypper /
// NewFlatpak) must still get input validation, even though they
// bypass the validatingManager wrapper that New() / Detect() install.
//
// We don't actually run package-manager binaries; the assertion is
// that the validation rejection happens **before** any command would
// have been executed. Each method returns on the validation error;
// the testcase passes if (and only if) we see that early-return.

type backendMaker struct {
	name string
	make func() Manager
}

func backends(t *testing.T) []backendMaker {
	t.Helper()
	return []backendMaker{
		{"apt", func() Manager { return NewApt() }},
		{"dnf", func() Manager { return NewDnf() }},
		{"pacman", func() Manager { return NewPacman() }},
		{"zypper", func() Manager { return NewZypper() }},
		{"flatpak", func() Manager { return NewFlatpak() }},
	}
}

// badNames covers the option-shape / shell-shape inputs the audit
// finding called out. A single name is enough — the validator runs
// over each entry of a list, so one rejection proves the loop runs.
var badNames = []struct {
	label string
	name  string
}{
	{"option-flag", "--force-yes"},
	{"shell-pipe", "vim|sh"},
	{"shell-redirect", "vim>/tmp/out"},
	{"backtick", "vim`whoami`"},
	{"dollar-paren", "vim$(whoami)"},
	{"semicolon", "vim;rm-rf"},
	{"glob-star", "vim*"},
	{"whitespace", "vim foo"},
	{"empty", ""},
}

func TestConcreteBackend_Install_RejectsBadName(t *testing.T) {
	for _, b := range backends(t) {
		for _, n := range badNames {
			t.Run(b.name+"/"+n.label, func(t *testing.T) {
				_, err := b.make().Install(n.name)
				if err == nil {
					t.Fatalf("Install(%q) on %s returned nil error — validation bypassed", n.name, b.name)
				}
				assertValidationError(t, err, n.name)
			})
		}
	}
}

func TestConcreteBackend_InstallVersion_RejectsBadName(t *testing.T) {
	for _, b := range backends(t) {
		for _, n := range badNames {
			if n.name == "" {
				continue // empty is the same as "Install with no args" — covered by InstallVersion(name, _)
			}
			t.Run(b.name+"/"+n.label, func(t *testing.T) {
				_, err := b.make().InstallVersion(n.name, InstallOptions{})
				if err == nil {
					t.Fatalf("InstallVersion(%q) on %s returned nil — validation bypassed", n.name, b.name)
				}
				assertValidationError(t, err, n.name)
			})
		}
	}
}

func TestConcreteBackend_InstallVersion_RejectsBadVersion(t *testing.T) {
	badVersions := []struct {
		label string
		ver   string
	}{
		{"option-flag", "--force"},
		{"shell-pipe", "1.0|evil"},
		{"backtick", "1.0`id`"},
		{"semicolon", "1.0;rm"},
		{"whitespace", "1.0 evil"},
	}
	for _, b := range backends(t) {
		for _, v := range badVersions {
			t.Run(b.name+"/"+v.label, func(t *testing.T) {
				_, err := b.make().InstallVersion("vim", InstallOptions{Version: v.ver})
				if err == nil {
					t.Fatalf("InstallVersion(vim, %q) on %s returned nil — version validation bypassed", v.ver, b.name)
				}
				if !strings.Contains(err.Error(), "version") {
					t.Errorf("error %q does not mention 'version' — wrong validator fired?", err)
				}
			})
		}
	}
}

func TestConcreteBackend_Remove_RejectsBadName(t *testing.T) {
	for _, b := range backends(t) {
		for _, n := range badNames {
			t.Run(b.name+"/"+n.label, func(t *testing.T) {
				_, err := b.make().Remove(n.name)
				if err == nil {
					t.Fatalf("Remove(%q) on %s returned nil — validation bypassed", n.name, b.name)
				}
				assertValidationError(t, err, n.name)
			})
		}
	}
}

func TestConcreteBackend_Upgrade_RejectsBadName(t *testing.T) {
	for _, b := range backends(t) {
		for _, n := range badNames {
			if n.name == "" {
				continue // Upgrade() with no packages is the "upgrade everything" path
			}
			t.Run(b.name+"/"+n.label, func(t *testing.T) {
				_, err := b.make().Upgrade(n.name)
				if err == nil {
					t.Fatalf("Upgrade(%q) on %s returned nil — validation bypassed", n.name, b.name)
				}
				assertValidationError(t, err, n.name)
			})
		}
	}
}

func TestConcreteBackend_Show_RejectsBadName(t *testing.T) {
	for _, b := range backends(t) {
		for _, n := range badNames {
			t.Run(b.name+"/"+n.label, func(t *testing.T) {
				_, err := b.make().Show(n.name)
				if err == nil {
					t.Fatalf("Show(%q) on %s returned nil — validation bypassed", n.name, b.name)
				}
				assertValidationError(t, err, n.name)
			})
		}
	}
}

func TestConcreteBackend_Pin_RejectsBadName(t *testing.T) {
	for _, b := range backends(t) {
		for _, n := range badNames {
			t.Run(b.name+"/"+n.label, func(t *testing.T) {
				_, err := b.make().Pin(n.name)
				if err == nil {
					t.Fatalf("Pin(%q) on %s returned nil — validation bypassed", n.name, b.name)
				}
				assertValidationError(t, err, n.name)
			})
		}
	}
}

func TestConcreteBackend_Unpin_RejectsBadName(t *testing.T) {
	for _, b := range backends(t) {
		for _, n := range badNames {
			t.Run(b.name+"/"+n.label, func(t *testing.T) {
				_, err := b.make().Unpin(n.name)
				if err == nil {
					t.Fatalf("Unpin(%q) on %s returned nil — validation bypassed", n.name, b.name)
				}
				assertValidationError(t, err, n.name)
			})
		}
	}
}

func assertValidationError(t *testing.T, err error, name string) {
	t.Helper()
	msg := err.Error()
	if name == "" {
		if !strings.Contains(msg, "empty") {
			t.Errorf("empty-name error %q does not look like a validation rejection", msg)
		}
		return
	}
	if !strings.Contains(msg, "invalid package name") {
		t.Errorf("error %q does not look like a ValidatePackageName rejection", msg)
	}
}
