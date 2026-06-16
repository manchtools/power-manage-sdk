//go:build linux

// Package inventory provides lightweight system inventory collection using
// standard Linux interfaces (/proc, /etc, standard tools) without requiring
// osquery. Command-backed collectors run through an injected exec.Runner.
//
//	r, _ := exec.NewRunner(exec.Direct)
//	inv, _ := inventory.New(r)
//	sys, _ := inv.System(ctx)
//
// Status: SDK-resident, single-consumer today (the agent's connect-time
// inventory snapshot). The package lives in the SDK rather than under
// agent/internal/sys because the planned server-side compliance preview needs
// the same parsers. F027 in TECH_DEBT_AUDIT.md.
package inventory

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// Seams for the file-backed sources, overridable from tests so the
// command-driven collectors can be exercised deterministically.
var (
	cpuinfoPath   = "/proc/cpuinfo"
	meminfoPath   = "/proc/meminfo"
	osReleasePath = "/etc/os-release"
	hostnameFn    = os.Hostname
)

// SystemInfo holds basic hardware and kernel information.
type SystemInfo struct {
	Hostname      string
	CPUModel      string
	CPUCores      int
	MemoryTotalMB int64
	Arch          string
	KernelVersion string
}

// OSInfo holds operating system identification details.
type OSInfo struct {
	Name       string // e.g. "Fedora Linux"
	Version    string // e.g. "43"
	ID         string // e.g. "fedora"
	PrettyName string // e.g. "Fedora Linux 43 (Workstation Edition)"
	VersionID  string // e.g. "43"
	Arch       string // e.g. "x86_64" (runtime.GOARCH)
}

// DiskInfo holds block device information.
type DiskInfo struct {
	Device string // e.g. "/dev/sda"
	Size   string // e.g. "500G" (human-readable from lsblk)
	Type   string // e.g. "disk", "part"
	Mount  string // e.g. "/"
}

// NetworkInterface holds network interface details.
type NetworkInterface struct {
	Name      string
	MAC       string
	Addresses []string // e.g. ["192.168.1.100/24", "fe80::1/64"]
	State     string   // "UP" or "DOWN"
}

// Collector gathers system inventory. Command-backed methods run through the
// injected Runner; OS() is a pure /etc/os-release read.
type Collector interface {
	System(ctx context.Context) (*SystemInfo, error)
	OS() (*OSInfo, error)
	Disks(ctx context.Context) ([]DiskInfo, error)
	NetworkInterfaces(ctx context.Context) ([]NetworkInterface, error)
}

// New returns a Collector driven by runner. A nil runner is rejected.
func New(runner exec.Runner) (Collector, error) {
	if runner == nil {
		return nil, errors.New("inventory: runner is required")
	}
	return &collector{r: runner}, nil
}

type collector struct {
	r exec.Runner
}

// read runs an unprivileged query and returns its stdout, mapping a non-zero
// exit (or a failure to execute) to an error.
func (c *collector) read(ctx context.Context, name string, args ...string) (string, error) {
	res, err := c.r.Run(ctx, exec.Command{Name: name, Args: args})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", &exec.CommandError{Name: name, ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return res.Stdout, nil
}

// System returns basic system information. Sources: hostname, /proc/cpuinfo,
// /proc/meminfo, runtime.GOARCH, uname -r.
func (c *collector) System(ctx context.Context) (*SystemInfo, error) {
	info := &SystemInfo{Arch: runtime.GOARCH}

	hostname, err := hostnameFn()
	if err != nil {
		return nil, fmt.Errorf("get hostname: %w", err)
	}
	info.Hostname = hostname

	cpuModel, cpuCores, err := parseCPUInfo(cpuinfoPath)
	if err != nil {
		return nil, fmt.Errorf("parse cpuinfo: %w", err)
	}
	info.CPUModel = cpuModel
	info.CPUCores = cpuCores

	memTotal, err := parseMemTotal(meminfoPath)
	if err != nil {
		return nil, fmt.Errorf("parse meminfo: %w", err)
	}
	info.MemoryTotalMB = memTotal

	out, err := c.read(ctx, "uname", "-r")
	if err != nil {
		return nil, fmt.Errorf("get kernel version: %w", err)
	}
	info.KernelVersion = strings.TrimSpace(out)

	return info, nil
}

// OS returns operating system details from /etc/os-release.
func (c *collector) OS() (*OSInfo, error) {
	info, err := parseOSRelease(osReleasePath)
	if err != nil {
		return nil, err
	}
	info.Arch = runtime.GOARCH
	return info, nil
}

// Disks returns block device information via lsblk --json.
func (c *collector) Disks(ctx context.Context) ([]DiskInfo, error) {
	out, err := c.read(ctx, "lsblk", "--json", "-o", "NAME,SIZE,TYPE,MOUNTPOINT")
	if err != nil {
		return nil, fmt.Errorf("run lsblk: %w", err)
	}

	type blockDevice struct {
		Name       string        `json:"name"`
		Size       string        `json:"size"`
		Type       string        `json:"type"`
		Mountpoint string        `json:"mountpoint"`
		Children   []blockDevice `json:"children"`
	}
	var output struct {
		Blockdevices []blockDevice `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(out), &output); err != nil {
		return nil, fmt.Errorf("parse lsblk output: %w", err)
	}

	var disks []DiskInfo
	var walk func(devices []blockDevice)
	walk = func(devices []blockDevice) {
		for _, bd := range devices {
			disks = append(disks, DiskInfo{
				Device: "/dev/" + bd.Name,
				Size:   bd.Size,
				Type:   bd.Type,
				Mount:  bd.Mountpoint,
			})
			if len(bd.Children) > 0 {
				walk(bd.Children)
			}
		}
	}
	walk(output.Blockdevices)
	return disks, nil
}

// NetworkInterfaces returns network interface details via ip -j addr.
func (c *collector) NetworkInterfaces(ctx context.Context) ([]NetworkInterface, error) {
	out, err := c.read(ctx, "ip", "-j", "addr")
	if err != nil {
		return nil, fmt.Errorf("run ip addr: %w", err)
	}

	var output []struct {
		IfName    string `json:"ifname"`
		Address   string `json:"address"`
		OperState string `json:"operstate"`
		AddrInfo  []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(out), &output); err != nil {
		return nil, fmt.Errorf("parse ip addr output: %w", err)
	}

	interfaces := make([]NetworkInterface, 0, len(output))
	for _, iface := range output {
		ni := NetworkInterface{
			Name:  iface.IfName,
			MAC:   iface.Address,
			State: strings.ToUpper(iface.OperState),
		}
		for _, addr := range iface.AddrInfo {
			ni.Addresses = append(ni.Addresses, fmt.Sprintf("%s/%d", addr.Local, addr.PrefixLen))
		}
		interfaces = append(interfaces, ni)
	}
	return interfaces, nil
}

// parseCPUInfo reads /proc/cpuinfo and extracts the CPU model name and core count.
func parseCPUInfo(path string) (model string, cores int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			if model == "" {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					model = strings.TrimSpace(parts[1])
				}
			}
		}
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	return model, cores, nil
}

// parseMemTotal reads /proc/meminfo and returns total memory in MB.
func parseMemTotal(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("unexpected MemTotal format: %s", line)
			}
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse MemTotal value: %w", err)
			}
			return kb / 1024, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("MemTotal not found in %s", path)
}

// parseOSRelease parses an os-release file and returns OSInfo.
func parseOSRelease(path string) (*OSInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open os-release: %w", err)
	}
	defer f.Close()

	info := &OSInfo{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := parseOSReleaseLine(scanner.Text())
		if !ok {
			continue
		}
		switch key {
		case "NAME":
			info.Name = value
		case "VERSION":
			info.Version = value
		case "ID":
			info.ID = value
		case "PRETTY_NAME":
			info.PrettyName = value
		case "VERSION_ID":
			info.VersionID = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return info, nil
}

// parseOSReleaseLine parses a single KEY=VALUE line from os-release. Values may be
// optionally quoted with double quotes.
func parseOSReleaseLine(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key = parts[0]
	value = parts[1]
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}
