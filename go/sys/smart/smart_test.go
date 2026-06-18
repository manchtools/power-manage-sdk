package smart

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func newColl(t *testing.T) (*collector, *exectest.FakeRunner) {
	t.Helper()
	r := exectest.New(exec.Direct)
	c, err := New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c.(*collector), r
}

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Error("New(nil) returned nil error")
	}
}

func TestValidateDevice(t *testing.T) {
	cases := map[string]bool{ // path -> valid
		"/dev/sda":     true,
		"/dev/nvme0n1": true,
		"":             false,
		"sda":          false, // not absolute
		"-rf":          false, // flag-shaped
		"/etc/passwd":  false, // absolute but NOT under /dev — escalated probe must not reach it
		"/dev/../etc":  false, // dotdot
		"/dev/s\x00a":  false, // NUL
	}
	for dev, valid := range cases {
		err := validateDevice(dev)
		if valid && err != nil {
			t.Errorf("validateDevice(%q) = %v, want nil", dev, err)
		}
		if !valid && err == nil {
			t.Errorf("validateDevice(%q) = nil, want error", dev)
		}
	}
}

func TestScan(t *testing.T) {
	c, r := newColl(t)
	r.Push(exec.Result{Stdout: `{"devices":[{"name":"/dev/sda","type":"sat"},{"name":"/dev/nvme0","type":"nvme"}]}`}, nil)
	devs, err := c.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(devs) != 2 || devs[0].Name != "/dev/sda" || devs[0].Type != "sat" || devs[1].Name != "/dev/nvme0" {
		t.Fatalf("Scan = %+v", devs)
	}
	if argv := strings.Join(r.Calls()[0].Args, " "); argv != "--scan -j" || !r.Calls()[0].Escalate {
		t.Errorf("scan argv = %q (escalate=%v), want escalated `--scan -j`", argv, r.Calls()[0].Escalate)
	}
}

func TestScan_RunError(t *testing.T) {
	c, r := newColl(t)
	r.Push(exec.Result{}, errors.New("smartctl not found"))
	if _, err := c.Scan(context.Background()); err == nil {
		t.Error("Scan must surface a Runner error")
	}
}

func TestScan_BadJSON(t *testing.T) {
	c, r := newColl(t)
	r.Push(exec.Result{Stdout: "not json"}, nil)
	if _, err := c.Scan(context.Background()); err == nil {
		t.Error("Scan must surface a parse error")
	}
}

func TestDevice_Success(t *testing.T) {
	c, r := newColl(t)
	r.Push(exec.Result{Stdout: `{"model_name":"Samsung SSD 870","serial_number":"S123",` +
		`"smart_status":{"passed":true},"temperature":{"current":35},"power_on_time":{"hours":1200},` +
		`"smartctl":{"exit_status":0}}`}, nil)
	d, err := c.Device(context.Background(), "/dev/sda")
	if err != nil {
		t.Fatalf("Device: %v", err)
	}
	want := Device{Name: "/dev/sda", Model: "Samsung SSD 870", Serial: "S123", Healthy: true, TemperatureC: 35, PowerOnHours: 1200}
	if d != want {
		t.Errorf("Device = %+v, want %+v", d, want)
	}
	if argv := strings.Join(r.Calls()[0].Args, " "); argv != "-j -a /dev/sda" || !r.Calls()[0].Escalate {
		t.Errorf("device argv = %q (escalate=%v)", argv, r.Calls()[0].Escalate)
	}
}

func TestDevice_UnhealthyStillReturned(t *testing.T) {
	// A failing self-assessment sets exit bits >= 4 (not fatal): the device is
	// reported with Healthy=false, NOT an error.
	c, r := newColl(t)
	r.Push(exec.Result{ExitCode: 8, Stdout: `{"model_name":"OldDisk","smart_status":{"passed":false},"smartctl":{"exit_status":8}}`}, nil)
	d, err := c.Device(context.Background(), "/dev/sda")
	if err != nil {
		t.Fatalf("Device must not error on an unhealthy-but-readable disk: %v", err)
	}
	if d.Healthy {
		t.Error("Healthy should be false for a failed self-assessment")
	}
}

func TestDevice_FatalBitsError(t *testing.T) {
	c, r := newColl(t)
	r.Push(exec.Result{ExitCode: 2, Stdout: `{"smartctl":{"exit_status":2,"messages":[{"string":"Smartctl open device: /dev/sdz failed"}]}}`}, nil)
	_, err := c.Device(context.Background(), "/dev/sdz")
	if err == nil || !strings.Contains(err.Error(), "open device") {
		t.Errorf("Device with a device-open failure must error naming it, got %v", err)
	}
}

func TestDevice_BadDevice(t *testing.T) {
	c, r := newColl(t)
	if _, err := c.Device(context.Background(), "-rf"); !errors.Is(err, ErrInvalidDevice) {
		t.Errorf("err = %v, want ErrInvalidDevice", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("a bad device must run nothing")
	}
}

func TestDevice_RunError(t *testing.T) {
	c, r := newColl(t)
	r.Push(exec.Result{}, errors.New("escalation denied"))
	if _, err := c.Device(context.Background(), "/dev/sda"); err == nil {
		t.Error("Device must surface a Runner error")
	}
}

func TestDevice_BadJSON(t *testing.T) {
	c, r := newColl(t)
	r.Push(exec.Result{Stdout: "garbage"}, nil)
	if _, err := c.Device(context.Background(), "/dev/sda"); err == nil {
		t.Error("Device must surface a parse error")
	}
}

func TestJoinMessages_Empty(t *testing.T) {
	if got := joinMessages(nil); got != "no diagnostic message" {
		t.Errorf("joinMessages(nil) = %q", got)
	}
}
