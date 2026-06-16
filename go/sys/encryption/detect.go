package encryption

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

type lsblkOutput struct {
	BlockDevices []lsblkDevice `json:"blockdevices"`
}

type lsblkDevice struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	FSType     *string       `json:"fstype"`
	MountPoint *string       `json:"mountpoint"`
	Children   []lsblkDevice `json:"children,omitempty"`
}

// DetectAllVolumes returns every LUKS volume on the system (lsblk -J; read-only,
// unprivileged).
func (l *luks) DetectAllVolumes(ctx context.Context) ([]Volume, error) {
	res, err := l.r.Run(ctx, exec.Command{Name: "lsblk", Args: []string{"-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"}})
	if err != nil {
		return nil, fmt.Errorf("lsblk: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, &exec.CommandError{Name: "lsblk", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	var output lsblkOutput
	if err := json.Unmarshal([]byte(res.Stdout), &output); err != nil {
		return nil, fmt.Errorf("parse lsblk output: %w", err)
	}
	var volumes []Volume
	findLuksVolumes(output.BlockDevices, &volumes)
	return volumes, nil
}

// DetectVolume auto-selects the primary LUKS volume: /home > / > first found.
func (l *luks) DetectVolume(ctx context.Context) (Volume, error) {
	volumes, err := l.DetectAllVolumes(ctx)
	if err != nil {
		return Volume{}, err
	}
	if len(volumes) == 0 {
		return Volume{}, fmt.Errorf("no LUKS-encrypted volumes detected on this device")
	}
	for _, want := range []string{"/home", "/"} {
		for i := range volumes {
			if volumes[i].MountPoint == want {
				return volumes[i], nil
			}
		}
	}
	return volumes[0], nil
}

// DetectVolumeByKey returns the LUKS volume that accepts p.
func (l *luks) DetectVolumeByKey(ctx context.Context, p exec.Secret) (Volume, error) {
	volumes, err := l.DetectAllVolumes(ctx)
	if err != nil {
		return Volume{}, err
	}
	if len(volumes) == 0 {
		return Volume{}, fmt.Errorf("no LUKS-encrypted volumes detected on this device")
	}
	for i := range volumes {
		ok, err := l.VerifyPassphrase(ctx, volumes[i].DevicePath, p)
		if err != nil {
			// A single untestable volume (permissions, transient error) must
			// not hide a match elsewhere — log and continue.
			slog.Warn("failed to test passphrase on LUKS volume; skipping", "device", volumes[i].DevicePath, "error", err)
			continue
		}
		if ok {
			return volumes[i], nil
		}
	}
	return Volume{}, fmt.Errorf("no LUKS volume accepts the provided passphrase")
}

func findLuksVolumes(devices []lsblkDevice, volumes *[]Volume) {
	for _, dev := range devices {
		fstype := ""
		if dev.FSType != nil {
			fstype = *dev.FSType
		}
		if fstype == "crypto_LUKS" {
			vol := Volume{DevicePath: "/dev/" + dev.Name}
			for _, child := range dev.Children {
				if child.Type == "crypt" {
					vol.MapperName = child.Name
					if child.MountPoint != nil && *child.MountPoint != "" {
						vol.MountPoint = *child.MountPoint
					}
					// LVM-on-LUKS: a grandchild holds the mount.
					for _, gc := range child.Children {
						if gc.MountPoint != nil && *gc.MountPoint != "" {
							vol.MountPoint = *gc.MountPoint
						}
					}
				}
			}
			*volumes = append(*volumes, vol)
		}
		if len(dev.Children) > 0 {
			findLuksVolumes(dev.Children, volumes)
		}
	}
}
