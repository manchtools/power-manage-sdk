package pkg

import (
	"slices"
	"testing"
)

// pacman has no "permit downgrade" flag — `pacman -S pkg=<older>` installs
// an explicit older version directly. The previous implementation injected
// `--overwrite "*"` for AllowDowngrade, which force-clobbers ANY conflicting
// file on disk, including files owned by OTHER packages. That blanket glob
// must not appear: a real file conflict should fail loudly, not silently
// overwrite unrelated files (the apt/zypper backends use the targeted
// --allow-downgrades / --oldpackage, not a wildcard overwrite).
func TestPacmanInstallVersionArgs_NoBlanketOverwrite(t *testing.T) {
	args := pacmanInstallVersionArgs("vim", "8.0.1")

	if slices.Contains(args, "--overwrite") {
		t.Errorf("argv must not contain --overwrite (blanket clobber): %v", args)
	}
	if slices.Contains(args, "*") {
		t.Errorf("argv must not contain the '*' overwrite glob: %v", args)
	}
	// It must still install the requested version spec non-interactively.
	if !slices.Contains(args, "vim=8.0.1") {
		t.Errorf("argv missing version spec vim=8.0.1: %v", args)
	}
	if !slices.Contains(args, "-S") || !slices.Contains(args, "--noconfirm") {
		t.Errorf("argv missing -S/--noconfirm: %v", args)
	}
}
