//go:build container

// Container-based real-execution tests for the inventory parsers. The fake-runner
// unit tests feed captured /proc, os-release, lsblk and `ip -j` output; these run
// the parsers against the REAL files and tools inside the container, so a kernel
// /proc format change, an os-release field change, or an iproute2/lsblk JSON
// shape change is caught here. Anti-rot guard. Self-skips nothing — /proc and
// /etc/os-release always exist; tool-backed methods need their binary (present
// in the test image).
package inventory

import (
	"context"
	"os"
	osexec "os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

func realCollector(t *testing.T) Collector {
	t.Helper()
	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	c, err := New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func invCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestSystem_ParsesRealProc_Container pins the /proc/cpuinfo + /proc/meminfo +
// uname parse against the real kernel.
func TestSystem_ParsesRealProc_Container(t *testing.T) {
	info, err := realCollector(t).System(invCtx(t))
	if err != nil {
		t.Fatalf("System: %v", err)
	}
	if info.Hostname == "" {
		t.Error("Hostname empty")
	}
	if info.CPUModel == "" {
		t.Error("CPUModel empty (parsed from /proc/cpuinfo)")
	}
	if info.CPUCores < 1 {
		t.Errorf("CPUCores = %d, want >= 1", info.CPUCores)
	}
	if info.MemoryTotalMB <= 0 {
		t.Errorf("MemoryTotalMB = %d, want > 0 (parsed from /proc/meminfo)", info.MemoryTotalMB)
	}
	out, err := osexec.Command("uname", "-r").Output()
	if err != nil {
		t.Fatalf("uname -r: %v", err)
	}
	if want := strings.TrimSpace(string(out)); info.KernelVersion != want {
		t.Errorf("KernelVersion = %q, want %q (real `uname -r`)", info.KernelVersion, want)
	}
}

// TestOS_ParsesRealOSRelease_Container pins the /etc/os-release parse against the
// real (debian) file.
func TestOS_ParsesRealOSRelease_Container(t *testing.T) {
	got, err := realCollector(t).OS()
	if err != nil {
		t.Fatalf("OS: %v", err)
	}
	// Independent verify: read the distro id from /etc/os-release ourselves (a
	// minimal parse, NOT the code under test) and assert the parser extracted the
	// SAME id. Distro-agnostic — no hardcoded "debian" — so it pins the real
	// os-release parse on every container in the matrix.
	wantID := osReleaseField(t, "ID")
	if wantID == "" {
		t.Fatal("could not read ID from /etc/os-release independently")
	}
	if got.ID != wantID {
		t.Errorf("OS.ID = %q, want %q (independently read from /etc/os-release)", got.ID, wantID)
	}
	if got.Name == "" || got.VersionID == "" {
		t.Errorf("OS Name/VersionID empty: %+v", got)
	}
	if got.Arch != runtime.GOARCH {
		t.Errorf("OS.Arch = %q, want %q", got.Arch, runtime.GOARCH)
	}
}

// osReleaseField reads one key from /etc/os-release with the test's own minimal
// parse, independent of the production parser, so the comparison is a real
// cross-check rather than echoing the code under test.
func osReleaseField(t *testing.T, key string) string {
	t.Helper()
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		t.Fatalf("read /etc/os-release: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// TestDisks_ParsesRealLsblk_Container pins the `lsblk --json` parse: it must
// decode real lsblk output without error.
func TestDisks_ParsesRealLsblk_Container(t *testing.T) {
	if _, err := osexec.LookPath("lsblk"); err != nil {
		t.Skip("lsblk not on PATH")
	}
	if _, err := realCollector(t).Disks(invCtx(t)); err != nil {
		t.Fatalf("Disks (real `lsblk --json` parse): %v", err)
	}
}

// TestNetworkInterfaces_ParsesRealIpJSON_Container pins the `ip -j addr` parse:
// loopback must be discovered.
func TestNetworkInterfaces_ParsesRealIpJSON_Container(t *testing.T) {
	if _, err := osexec.LookPath("ip"); err != nil {
		t.Skip("iproute2 `ip` not on PATH")
	}
	ifaces, err := realCollector(t).NetworkInterfaces(invCtx(t))
	if err != nil {
		t.Fatalf("NetworkInterfaces (real `ip -j addr` parse): %v", err)
	}
	found := false
	for _, i := range ifaces {
		if i.Name == "lo" {
			found = true
		}
	}
	if !found {
		t.Errorf("loopback 'lo' not found in parsed interfaces: %+v", ifaces)
	}
}
