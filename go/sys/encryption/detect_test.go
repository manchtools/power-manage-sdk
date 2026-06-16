package encryption

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

func strptr(s string) *string { return &s }

// findLuksVolumes — pure tree-walk over lsblk's structure.
func TestFindLuksVolumes(t *testing.T) {
	t.Run("single unlocked, mounted via crypt child", func(t *testing.T) {
		devs := []lsblkDevice{{
			Name: "sda2", Type: "part", FSType: strptr("crypto_LUKS"),
			Children: []lsblkDevice{{Name: "luks-1", Type: "crypt", MountPoint: strptr("/home")}},
		}}
		var vols []Volume
		findLuksVolumes(devs, &vols)
		if len(vols) != 1 || vols[0].DevicePath != "/dev/sda2" || vols[0].MapperName != "luks-1" || vols[0].MountPoint != "/home" {
			t.Fatalf("vols = %+v", vols)
		}
	})
	t.Run("none", func(t *testing.T) {
		var vols []Volume
		findLuksVolumes([]lsblkDevice{{Name: "sda1", Type: "part", FSType: strptr("ext4")}}, &vols)
		if len(vols) != 0 {
			t.Errorf("vols = %+v, want none", vols)
		}
	})
	t.Run("locked (no crypt child)", func(t *testing.T) {
		var vols []Volume
		findLuksVolumes([]lsblkDevice{{Name: "sda2", Type: "part", FSType: strptr("crypto_LUKS")}}, &vols)
		if len(vols) != 1 || vols[0].MapperName != "" || vols[0].MountPoint != "" {
			t.Fatalf("locked volume = %+v, want device path only", vols)
		}
	})
	t.Run("LVM-on-LUKS: mount comes from grandchild", func(t *testing.T) {
		devs := []lsblkDevice{{
			Name: "sda2", Type: "part", FSType: strptr("crypto_LUKS"),
			Children: []lsblkDevice{{
				Name: "luks-1", Type: "crypt",
				Children: []lsblkDevice{{Name: "vg-root", Type: "lvm", MountPoint: strptr("/")}},
			}},
		}}
		var vols []Volume
		findLuksVolumes(devs, &vols)
		if len(vols) != 1 || vols[0].MountPoint != "/" {
			t.Fatalf("LVM-on-LUKS = %+v, want MountPoint / from grandchild", vols)
		}
	})
}

const lsblkTwoVolumes = `{"blockdevices":[
  {"name":"sda2","type":"part","fstype":"crypto_LUKS","children":[{"name":"luks-root","type":"crypt","mountpoint":"/"}]},
  {"name":"sdb1","type":"part","fstype":"crypto_LUKS","children":[{"name":"luks-home","type":"crypt","mountpoint":"/home"}]}
]}`

func TestDetectAllVolumes(t *testing.T) {
	t.Run("parses lsblk JSON (unescalated)", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: lsblkTwoVolumes}, nil)
		vols, err := mgr(t, r).DetectAllVolumes(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(vols) != 2 {
			t.Fatalf("got %d volumes, want 2", len(vols))
		}
		if c := r.calls[0].cmd; c.Name != "lsblk" || c.Escalate {
			t.Errorf("lsblk call = %+v, want unescalated lsblk", c)
		}
	})
	t.Run("bad JSON errors", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: "not json"}, nil)
		if _, err := mgr(t, r).DetectAllVolumes(context.Background()); err == nil {
			t.Error("DetectAllVolumes accepted non-JSON output")
		}
	})
	t.Run("lsblk non-zero exit errors", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 1, Stderr: "lsblk: bad option"}, nil)
		if _, err := mgr(t, r).DetectAllVolumes(context.Background()); err == nil {
			t.Error("DetectAllVolumes ignored a non-zero lsblk exit")
		}
	})
	t.Run("lsblk exec error", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{}, exec.ErrEscalationUnavailable)
		if _, err := mgr(t, r).DetectAllVolumes(context.Background()); err == nil {
			t.Error("DetectAllVolumes ignored an lsblk exec error")
		}
	})
}

func TestDetectVolume_Priority(t *testing.T) {
	t.Run("prefers /home", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: lsblkTwoVolumes}, nil)
		v, err := mgr(t, r).DetectVolume(context.Background())
		if err != nil || v.MountPoint != "/home" {
			t.Fatalf("DetectVolume = (%+v,%v), want /home", v, err)
		}
	})
	t.Run("falls back to /", func(t *testing.T) {
		const onlyRoot = `{"blockdevices":[{"name":"sda2","type":"part","fstype":"crypto_LUKS","children":[{"name":"l","type":"crypt","mountpoint":"/"}]}]}`
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: onlyRoot}, nil)
		v, _ := mgr(t, r).DetectVolume(context.Background())
		if v.MountPoint != "/" {
			t.Errorf("DetectVolume = %+v, want /", v)
		}
	})
	t.Run("falls back to first when no /home or /", func(t *testing.T) {
		const noStd = `{"blockdevices":[{"name":"sdc1","type":"part","fstype":"crypto_LUKS","children":[{"name":"l","type":"crypt","mountpoint":"/data"}]}]}`
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: noStd}, nil)
		v, _ := mgr(t, r).DetectVolume(context.Background())
		if v.DevicePath != "/dev/sdc1" {
			t.Errorf("DetectVolume = %+v, want first (/dev/sdc1)", v)
		}
	})
	t.Run("no volumes errors", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: `{"blockdevices":[]}`}, nil)
		if _, err := mgr(t, r).DetectVolume(context.Background()); err == nil {
			t.Error("DetectVolume returned nil error with no LUKS volumes")
		}
	})
}

func TestDetectVolumeByKey(t *testing.T) {
	t.Run("returns the volume that accepts the passphrase", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: lsblkTwoVolumes}, nil) // DetectAllVolumes
		r.push(exec.Result{ExitCode: 2}, nil)             // sda2: wrong passphrase
		r.push(exec.Result{ExitCode: 0}, nil)             // sdb1: accepts
		v, err := mgr(t, r).DetectVolumeByKey(context.Background(), mustSecret(t, "p"))
		if err != nil {
			t.Fatal(err)
		}
		if v.DevicePath != "/dev/sdb1" {
			t.Errorf("matched %+v, want /dev/sdb1", v)
		}
	})
	t.Run("no volume accepts → error", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: lsblkTwoVolumes}, nil)
		r.push(exec.Result{ExitCode: 2}, nil)
		r.push(exec.Result{ExitCode: 2}, nil)
		if _, err := mgr(t, r).DetectVolumeByKey(context.Background(), mustSecret(t, "p")); err == nil {
			t.Error("DetectVolumeByKey returned nil when no volume matched")
		}
	})
	t.Run("a per-volume test error is skipped, not fatal", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: lsblkTwoVolumes}, nil)
		r.push(exec.Result{ExitCode: 4}, nil) // sda2: error (skip, not abort)
		r.push(exec.Result{ExitCode: 0}, nil) // sdb1: accepts
		v, err := mgr(t, r).DetectVolumeByKey(context.Background(), mustSecret(t, "p"))
		if err != nil || v.DevicePath != "/dev/sdb1" {
			t.Errorf("DetectVolumeByKey = (%+v,%v), want sdb1 despite sda2 erroring", v, err)
		}
	})
	t.Run("no volumes errors", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{Stdout: `{"blockdevices":[]}`}, nil)
		if _, err := mgr(t, r).DetectVolumeByKey(context.Background(), mustSecret(t, "p")); err == nil {
			t.Error("DetectVolumeByKey returned nil with no volumes")
		}
	})
}

// sanity: the recordingRunner's lsblk arg is the read-only column set.
func TestDetectAllVolumes_LsblkArgs(t *testing.T) {
	r := &recordingRunner{}
	r.push(exec.Result{Stdout: `{"blockdevices":[]}`}, nil)
	_, _ = mgr(t, r).DetectAllVolumes(context.Background())
	if got := strings.Join(r.calls[0].cmd.Args, " "); got != "-J -o NAME,TYPE,FSTYPE,MOUNTPOINT" {
		t.Errorf("lsblk args = %q", got)
	}
}
