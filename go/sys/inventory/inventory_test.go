//go:build linux

package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func newCollector(t *testing.T, r exec.Runner) Collector {
	t.Helper()
	c, err := New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// writeTemp writes content to a temp file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
	}
}

func TestSystem(t *testing.T) {
	cpu := strings.Join([]string{
		"processor\t: 0", "model name\t: Test CPU",
		"processor\t: 1", "model name\t: Test CPU",
	}, "\n")
	restore := func() func() {
		oc, om, oh := cpuinfoPath, meminfoPath, hostnameFn
		cpuinfoPath = writeTemp(t, cpu)
		meminfoPath = writeTemp(t, "MemTotal:       16384000 kB\n")
		hostnameFn = func() (string, error) { return "host01", nil }
		return func() { cpuinfoPath, meminfoPath, hostnameFn = oc, om, oh }
	}()
	t.Cleanup(restore)

	t.Run("success", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{Stdout: "6.1.0-test\n"}, nil) // uname -r
		info, err := newCollector(t, r).System(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if info.Hostname != "host01" || info.CPUModel != "Test CPU" || info.CPUCores != 2 ||
			info.MemoryTotalMB != 16000 || info.KernelVersion != "6.1.0-test" || info.Arch == "" {
			t.Errorf("info = %+v", info)
		}
		if cmd := r.Calls()[0]; cmd.Name != "uname" || cmd.Escalate {
			t.Errorf("command = %+v, want unprivileged uname", cmd)
		}
	})

	t.Run("hostname error", func(t *testing.T) {
		oh := hostnameFn
		hostnameFn = func() (string, error) { return "", errors.New("no hostname") }
		t.Cleanup(func() { hostnameFn = oh })
		if _, err := newCollector(t, exectest.New(exec.Direct)).System(context.Background()); err == nil {
			t.Error("System ignored a hostname failure")
		}
	})

	t.Run("cpuinfo missing", func(t *testing.T) {
		oc := cpuinfoPath
		cpuinfoPath = filepath.Join(t.TempDir(), "nope")
		t.Cleanup(func() { cpuinfoPath = oc })
		if _, err := newCollector(t, exectest.New(exec.Direct)).System(context.Background()); err == nil {
			t.Error("System ignored a missing cpuinfo")
		}
	})

	t.Run("meminfo missing", func(t *testing.T) {
		om := meminfoPath
		meminfoPath = filepath.Join(t.TempDir(), "nope")
		t.Cleanup(func() { meminfoPath = om })
		if _, err := newCollector(t, exectest.New(exec.Direct)).System(context.Background()); err == nil {
			t.Error("System ignored a missing meminfo")
		}
	})

	t.Run("uname failure", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{ExitCode: 1, Stderr: "boom"}, nil)
		if _, err := newCollector(t, r).System(context.Background()); err == nil {
			t.Error("System ignored a uname failure")
		}
	})
}

func TestOS(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		op := osReleasePath
		osReleasePath = writeTemp(t, "ID=fedora\nPRETTY_NAME=\"Fedora Linux 43\"\n")
		t.Cleanup(func() { osReleasePath = op })
		info, err := newCollector(t, exectest.New(exec.Direct)).OS()
		if err != nil {
			t.Fatal(err)
		}
		if info.ID != "fedora" || info.PrettyName != "Fedora Linux 43" || info.Arch == "" {
			t.Errorf("info = %+v", info)
		}
	})
	t.Run("missing os-release", func(t *testing.T) {
		op := osReleasePath
		osReleasePath = filepath.Join(t.TempDir(), "nope")
		t.Cleanup(func() { osReleasePath = op })
		if _, err := newCollector(t, exectest.New(exec.Direct)).OS(); err == nil {
			t.Error("OS ignored a missing os-release")
		}
	})
}

func TestDisks(t *testing.T) {
	t.Run("success with nested children", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{Stdout: `{"blockdevices":[
			{"name":"sda","size":"500G","type":"disk","mountpoint":null,
			 "children":[{"name":"sda1","size":"500G","type":"part","mountpoint":"/"}]}
		]}`}, nil)
		disks, err := newCollector(t, r).Disks(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(disks) != 2 || disks[0].Device != "/dev/sda" || disks[1].Device != "/dev/sda1" || disks[1].Mount != "/" {
			t.Errorf("disks = %+v", disks)
		}
	})
	t.Run("run failure", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{ExitCode: 1}, nil)
		if _, err := newCollector(t, r).Disks(context.Background()); err == nil {
			t.Error("Disks ignored an lsblk failure")
		}
	})
	t.Run("parse failure", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{Stdout: "not json"}, nil)
		if _, err := newCollector(t, r).Disks(context.Background()); err == nil {
			t.Error("Disks ignored unparseable lsblk output")
		}
	})
}

func TestNetworkInterfaces(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{Stdout: `[
			{"ifname":"lo","address":"00:00:00:00:00:00","operstate":"unknown",
			 "addr_info":[{"local":"127.0.0.1","prefixlen":8}]},
			{"ifname":"eth0","address":"aa:bb:cc:dd:ee:ff","operstate":"up",
			 "addr_info":[{"local":"192.168.1.5","prefixlen":24}]}
		]`}, nil)
		ifaces, err := newCollector(t, r).NetworkInterfaces(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(ifaces) != 2 || ifaces[0].Name != "lo" || ifaces[1].State != "UP" ||
			len(ifaces[1].Addresses) != 1 || ifaces[1].Addresses[0] != "192.168.1.5/24" {
			t.Errorf("ifaces = %+v", ifaces)
		}
	})
	t.Run("run failure", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{}, errors.New("ip not found"))
		if _, err := newCollector(t, r).NetworkInterfaces(context.Background()); err == nil {
			t.Error("NetworkInterfaces ignored an ip failure")
		}
	})
	t.Run("parse failure", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{Stdout: "not json"}, nil)
		if _, err := newCollector(t, r).NetworkInterfaces(context.Background()); err == nil {
			t.Error("NetworkInterfaces ignored unparseable ip output")
		}
	})
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
