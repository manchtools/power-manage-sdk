package inventory

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestGetSystemInfo(t *testing.T) {
	ctx := context.Background()
	info, err := GetSystemInfo(ctx)
	if err != nil {
		t.Fatalf("GetSystemInfo() error: %v", err)
	}

	if info.Hostname == "" {
		t.Error("Hostname is empty")
	}
	if info.CPUModel == "" {
		t.Error("CPUModel is empty")
	}
	if info.CPUCores <= 0 {
		t.Errorf("CPUCores = %d, want > 0", info.CPUCores)
	}
	if info.MemoryTotalMB <= 0 {
		t.Errorf("MemoryTotalMB = %d, want > 0", info.MemoryTotalMB)
	}
	if info.Arch == "" {
		t.Error("Arch is empty")
	}
	if info.KernelVersion == "" {
		t.Error("KernelVersion is empty")
	}
}

func TestGetOSInfo(t *testing.T) {
	info, err := GetOSInfo()
	if err != nil {
		t.Fatalf("GetOSInfo() error: %v", err)
	}

	if info.ID == "" {
		t.Error("ID is empty")
	}
	if info.PrettyName == "" {
		t.Error("PrettyName is empty")
	}
}

func TestGetDisks(t *testing.T) {
	ctx := context.Background()
	disks, err := GetDisks(ctx)
	if err != nil {
		t.Fatalf("GetDisks() error: %v", err)
	}

	if len(disks) == 0 {
		t.Fatal("expected at least one disk")
	}

	for _, d := range disks {
		if d.Device == "" {
			t.Error("disk Device is empty")
		}
		if d.Type == "" {
			t.Error("disk Type is empty")
		}
	}
}

func TestGetNetworkInterfaces(t *testing.T) {
	ctx := context.Background()
	ifaces, err := GetNetworkInterfaces(ctx)
	if err != nil {
		t.Fatalf("GetNetworkInterfaces() error: %v", err)
	}

	if len(ifaces) == 0 {
		t.Fatal("expected at least one interface")
	}

	// Loopback should always exist.
	found := false
	for _, iface := range ifaces {
		if iface.Name == "lo" {
			found = true
			break
		}
	}
	if !found {
		t.Error("loopback interface (lo) not found")
	}
}

func TestParseOSRelease(t *testing.T) {
	content := `NAME="Fedora Linux"
VERSION="43 (Workstation Edition)"
ID=fedora
VERSION_ID=43
PRETTY_NAME="Fedora Linux 43 (Workstation Edition)"
# This is a comment
VARIANT_ID=workstation
`
	tmpFile, err := os.CreateTemp("", "os-release-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	tmpFile.Close()

	info, err := parseOSRelease(tmpFile.Name())
	if err != nil {
		t.Fatalf("parseOSRelease() error: %v", err)
	}

	if info.Name != "Fedora Linux" {
		t.Errorf("Name = %q, want %q", info.Name, "Fedora Linux")
	}
	if info.Version != "43 (Workstation Edition)" {
		t.Errorf("Version = %q, want %q", info.Version, "43 (Workstation Edition)")
	}
	if info.ID != "fedora" {
		t.Errorf("ID = %q, want %q", info.ID, "fedora")
	}
	if info.VersionID != "43" {
		t.Errorf("VersionID = %q, want %q", info.VersionID, "43")
	}
	if info.PrettyName != "Fedora Linux 43 (Workstation Edition)" {
		t.Errorf("PrettyName = %q, want %q", info.PrettyName, "Fedora Linux 43 (Workstation Edition)")
	}
}

func TestParseOSReleaseLine(t *testing.T) {
	tests := []struct {
		line    string
		wantKey string
		wantVal string
		wantOK  bool
	}{
		{`NAME="Fedora Linux"`, "NAME", "Fedora Linux", true},
		{`ID=fedora`, "ID", "fedora", true},
		{`# comment`, "", "", false},
		{``, "", "", false},
		{`EMPTY_VALUE=`, "EMPTY_VALUE", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			key, val, ok := parseOSReleaseLine(tt.line)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if key != tt.wantKey {
				t.Errorf("key = %q, want %q", key, tt.wantKey)
			}
			if val != tt.wantVal {
				t.Errorf("val = %q, want %q", val, tt.wantVal)
			}
		})
	}
}

func TestParseCPUInfo(t *testing.T) {
	content := strings.Join([]string{
		"processor\t: 0",
		"model name\t: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz",
		"",
		"processor\t: 1",
		"model name\t: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz",
		"",
	}, "\n")

	tmpFile, err := os.CreateTemp("", "cpuinfo-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	tmpFile.Close()

	model, cores, err := parseCPUInfo(tmpFile.Name())
	if err != nil {
		t.Fatalf("parseCPUInfo() error: %v", err)
	}
	if model != "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz" {
		t.Errorf("model = %q, want Intel i7", model)
	}
	if cores != 2 {
		t.Errorf("cores = %d, want 2", cores)
	}
}

func TestParseMemTotal(t *testing.T) {
	content := "MemTotal:       16384000 kB\nMemFree:         8192000 kB\n"

	tmpFile, err := os.CreateTemp("", "meminfo-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	tmpFile.Close()

	mb, err := parseMemTotal(tmpFile.Name())
	if err != nil {
		t.Fatalf("parseMemTotal() error: %v", err)
	}
	// 16384000 kB / 1024 = 16000 MB
	if mb != 16000 {
		t.Errorf("MemoryTotalMB = %d, want 16000", mb)
	}
}
