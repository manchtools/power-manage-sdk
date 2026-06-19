// Package smart reads S.M.A.R.T. disk health via smartctl (smartmontools)
// through an injected exec.Runner.
//
//	r, _ := exec.NewRunner(exec.Direct) // smartctl needs root
//	c, err := smart.New(r)
//	if err != nil { ... }
//	devs, _ := c.Scan(ctx)
//	for _, d := range devs {
//	    info, _ := c.Device(ctx, d.Name)
//	    fmt.Println(info.Name, info.Healthy, info.TemperatureC)
//	}
//
// smart is a single-implementation, read-only Collector (§3.8): smartctl is the
// one tool. It exposes an interface for shape-uniformity with the rest of the
// SDK. Probes escalate through the Runner (smartctl needs root to open a device).
package smart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// ErrInvalidDevice is returned when a device path is unsafe to pass to smartctl
// (empty, not absolute, contains "..", or flag-shaped).
var ErrInvalidDevice = errors.New("smart: invalid device path")

// ScanDevice is one entry from `smartctl --scan`.
type ScanDevice struct {
	Name string // e.g. /dev/sda
	Type string // smartctl device type, e.g. "sat", "nvme"
}

// Device is the parsed health summary for one device.
type Device struct {
	Name         string // the device passed to Device()
	Model        string
	Serial       string
	Healthy      bool // smart_status.passed
	TemperatureC int  // temperature.current (0 if unreported)
	PowerOnHours int  // power_on_time.hours (0 if unreported)
}

// Collector is the S.M.A.R.T. read surface.
type Collector interface {
	// Scan lists the devices smartctl can inspect.
	Scan(ctx context.Context) ([]ScanDevice, error)
	// Device returns the health summary for one device path.
	Device(ctx context.Context, dev string) (Device, error)
}

type collector struct {
	r exec.Runner
}

// New builds a smart Collector driven by runner. A nil runner is rejected. New is
// pure — it does not probe for smartctl (a missing binary surfaces at call time).
func New(runner exec.Runner) (Collector, error) {
	if runner == nil {
		return nil, fmt.Errorf("smart: %w", exec.ErrRunnerRequired)
	}
	return &collector{r: runner}, nil
}

// validateDevice rejects a device path that is unsafe to pass to escalated
// smartctl. It must be under /dev/ (smartctl inspects block devices; restricting
// to /dev keeps the privileged probe off arbitrary files like /etc/passwd),
// contain no ".." traversal, and no NUL. The /dev/ prefix also rules out a
// flag-shaped argument.
func validateDevice(dev string) error {
	if !strings.HasPrefix(dev, "/dev/") || strings.Contains(dev, "..") || strings.ContainsRune(dev, 0) {
		return fmt.Errorf("%w: %q (must be a /dev/* path with no '..')", ErrInvalidDevice, dev)
	}
	return nil
}

// scanResult mirrors `smartctl --scan -j`.
type scanResult struct {
	Devices []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"devices"`
}

// Scan lists inspectable devices.
func (c *collector) Scan(ctx context.Context) ([]ScanDevice, error) {
	out, err := c.run(ctx, "--scan", "-j")
	if err != nil {
		return nil, err
	}
	var sr scanResult
	if err := json.Unmarshal([]byte(out), &sr); err != nil {
		return nil, fmt.Errorf("smart: parse scan output: %w", err)
	}
	devs := make([]ScanDevice, 0, len(sr.Devices))
	for _, d := range sr.Devices {
		devs = append(devs, ScanDevice{Name: d.Name, Type: d.Type})
	}
	return devs, nil
}

// deviceResult mirrors the subset of `smartctl -j -a <dev>` we consume.
type deviceResult struct {
	ModelName    string `json:"model_name"`
	SerialNumber string `json:"serial_number"`
	SMARTStatus  struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime struct {
		Hours int `json:"hours"`
	} `json:"power_on_time"`
	Smartctl struct {
		ExitStatus int `json:"exit_status"`
		Messages   []struct {
			String string `json:"string"`
		} `json:"messages"`
	} `json:"smartctl"`
}

// smartctlFatalBits are the smartctl exit-status bits that mean the COMMAND
// failed (bit 0 = command-line parse error, bit 1 = device open failed). Bits 2+
// report device/SMART health (e.g. failing self-assessment) and are NOT execution
// failures — smart_status.passed already conveys health, so they must not be
// treated as an error.
const smartctlFatalBits = 0x03

// Device returns the health summary for dev.
func (c *collector) Device(ctx context.Context, dev string) (Device, error) {
	if err := validateDevice(dev); err != nil {
		return Device{}, err
	}
	out, err := c.run(ctx, "-j", "-a", dev)
	if err != nil {
		return Device{}, err
	}
	var dr deviceResult
	if err := json.Unmarshal([]byte(out), &dr); err != nil {
		return Device{}, fmt.Errorf("smart: parse device output for %s: %w", dev, err)
	}
	if dr.Smartctl.ExitStatus&smartctlFatalBits != 0 {
		return Device{}, fmt.Errorf("smart: smartctl could not inspect %s: %s", dev, joinMessages(dr.Smartctl.Messages))
	}
	return Device{
		Name:         dev,
		Model:        dr.ModelName,
		Serial:       dr.SerialNumber,
		Healthy:      dr.SMARTStatus.Passed,
		TemperatureC: dr.Temperature.Current,
		PowerOnHours: dr.PowerOnTime.Hours,
	}, nil
}

// run executes smartctl escalated and returns stdout. smartctl's non-zero exit
// is a HEALTH bitmask, not (usually) an exec failure, so we do not treat a
// non-zero exit as an error here — the caller's JSON parse + the fatal-bits check
// classify it. A nil error from the Runner with empty stdout still yields a parse
// error downstream. Only a Runner-level failure (binary missing, escalation
// denied) is surfaced here.
func (c *collector) run(ctx context.Context, args ...string) (string, error) {
	res, err := c.r.Run(ctx, exec.Command{Name: "smartctl", Args: args, Escalate: true})
	if err != nil {
		return "", fmt.Errorf("smart: run smartctl: %w", err)
	}
	return res.Stdout, nil
}

// joinMessages flattens smartctl's message strings for an error.
func joinMessages(msgs []struct {
	String string `json:"string"`
}) string {
	parts := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if s := strings.TrimSpace(m.String); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "no diagnostic message"
	}
	return strings.Join(parts, "; ")
}
