package archtest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// shippedSystemPackages is the exact target-design inventory. A capability is
// removed only by an explicit product decision, never because it currently has
// no agent importer.
var shippedSystemPackages = []string{
	"antivirus",
	"catrust",
	"desktop",
	"dns",
	"encryption",
	"exec",
	"firewall",
	"fs",
	"inventory",
	"log",
	"netconfig",
	"network",
	"notify",
	"osquery",
	"reboot",
	"remote",
	"repo",
	"service",
	"smart",
	"terminal",
	"timesync",
	"user",
}

// forwardSystemPackages are deliberately shipped even though the agent does
// not import them yet. Keeping this as a named exact set prevents cleanup work
// from mistaking planned product surface for dead code.
var forwardSystemPackages = []string{
	"antivirus",
	"catrust",
	"dns",
	"firewall",
	"netconfig",
	"smart",
	"timesync",
}

func TestSystemCapabilityInventoryIsExact(t *testing.T) {
	sysDir := filepath.Join(moduleRoot(t), "sys")
	entries, err := os.ReadDir(sysDir)
	if err != nil {
		t.Fatalf("read system capability directory: %v", err)
	}

	var got []string
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasPrefix(entry.Name(), "_") {
			continue
		}
		productionFiles, err := filepath.Glob(filepath.Join(sysDir, entry.Name(), "*.go"))
		if err != nil {
			t.Fatalf("inspect system package %s: %v", entry.Name(), err)
		}
		hasProductionFile := false
		for _, path := range productionFiles {
			if !strings.HasSuffix(path, "_test.go") {
				hasProductionFile = true
				break
			}
		}
		if hasProductionFile {
			got = append(got, entry.Name())
		}
	}

	if !slices.Equal(got, shippedSystemPackages) {
		t.Fatalf("shipped SDK system packages = %v, want exact target inventory %v", got, shippedSystemPackages)
	}
	if len(forwardSystemPackages) != 7 {
		t.Fatalf("forward capability inventory has %d packages, want exactly 7", len(forwardSystemPackages))
	}
	for _, name := range forwardSystemPackages {
		if !slices.Contains(shippedSystemPackages, name) {
			t.Errorf("forward capability %q is absent from the shipped inventory", name)
		}
	}
}
