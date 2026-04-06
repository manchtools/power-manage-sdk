// Package inventory provides lightweight system inventory collection using
// standard Linux interfaces (/proc, /etc, standard tools) without requiring
// osquery.
package inventory

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"

	"context"
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

// GetSystemInfo returns basic system information.
// Sources: hostname(), /proc/cpuinfo, /proc/meminfo, runtime.GOARCH, uname -r.
func GetSystemInfo(ctx context.Context) (*SystemInfo, error) {
	info := &SystemInfo{
		Arch: runtime.GOARCH,
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("get hostname: %w", err)
	}
	info.Hostname = hostname

	cpuModel, cpuCores, err := parseCPUInfo("/proc/cpuinfo")
	if err != nil {
		return nil, fmt.Errorf("parse cpuinfo: %w", err)
	}
	info.CPUModel = cpuModel
	info.CPUCores = cpuCores

	memTotal, err := parseMemTotal("/proc/meminfo")
	if err != nil {
		return nil, fmt.Errorf("parse meminfo: %w", err)
	}
	info.MemoryTotalMB = memTotal

	result, err := exec.Run(ctx, "uname", "-r")
	if err != nil {
		return nil, fmt.Errorf("get kernel version: %w", err)
	}
	info.KernelVersion = strings.TrimSpace(result.Stdout)

	return info, nil
}

// parseCPUInfo reads /proc/cpuinfo and extracts the CPU model name and core
// count.
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

// OSInfo holds operating system identification details.
type OSInfo struct {
	Name       string // e.g. "Fedora Linux"
	Version    string // e.g. "43"
	ID         string // e.g. "fedora"
	PrettyName string // e.g. "Fedora Linux 43 (Workstation Edition)"
	VersionID  string // e.g. "43"
}

// GetOSInfo returns operating system details from /etc/os-release.
func GetOSInfo() (*OSInfo, error) {
	return parseOSRelease("/etc/os-release")
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
		line := scanner.Text()
		key, value, ok := parseOSReleaseLine(line)
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

// parseOSReleaseLine parses a single KEY=VALUE line from os-release.
// Values may be optionally quoted with double quotes.
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
	// Remove surrounding quotes if present.
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}

// DiskInfo holds block device information.
type DiskInfo struct {
	Device string // e.g. "/dev/sda"
	Size   string // e.g. "500G" (human-readable from lsblk)
	Type   string // e.g. "disk", "part"
	Mount  string // e.g. "/"
}

// GetDisks returns block device information via lsblk --json.
func GetDisks(ctx context.Context) ([]DiskInfo, error) {
	result, err := exec.Run(ctx, "lsblk", "--json", "-o", "NAME,SIZE,TYPE,MOUNTPOINT")
	if err != nil {
		return nil, fmt.Errorf("run lsblk: %w", err)
	}

	var output struct {
		Blockdevices []struct {
			Name       string `json:"name"`
			Size       string `json:"size"`
			Type       string `json:"type"`
			Mountpoint string `json:"mountpoint"`
		} `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &output); err != nil {
		return nil, fmt.Errorf("parse lsblk output: %w", err)
	}

	disks := make([]DiskInfo, 0, len(output.Blockdevices))
	for _, bd := range output.Blockdevices {
		disks = append(disks, DiskInfo{
			Device: "/dev/" + bd.Name,
			Size:   bd.Size,
			Type:   bd.Type,
			Mount:  bd.Mountpoint,
		})
	}
	return disks, nil
}

// NetworkInterface holds network interface details.
type NetworkInterface struct {
	Name      string
	MAC       string
	Addresses []string // e.g. ["192.168.1.100/24", "fe80::1/64"]
	State     string   // "UP" or "DOWN"
}

// GetNetworkInterfaces returns network interface details via ip -j addr.
func GetNetworkInterfaces(ctx context.Context) ([]NetworkInterface, error) {
	result, err := exec.Run(ctx, "ip", "-j", "addr")
	if err != nil {
		return nil, fmt.Errorf("run ip addr: %w", err)
	}

	var output []struct {
		IfName    string   `json:"ifname"`
		Address   string   `json:"address"`
		OperState string   `json:"operstate"`
		Flags     []string `json:"flags"`
		AddrInfo  []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &output); err != nil {
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
