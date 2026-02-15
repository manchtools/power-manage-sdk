package luks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// Volume represents a detected LUKS-encrypted volume.
type Volume struct {
	DevicePath string // e.g., "/dev/sda2"
	MapperName string // e.g., "luks-xxxx" (empty if locked)
	MountPoint string // e.g., "/home" (of the unlocked dm device, empty if locked)
}

// lsblkOutput is the JSON output of lsblk.
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

// DetectVolume auto-detects the primary LUKS volume on the system.
// Priority: volume with /home mounted > volume with / mounted > first found.
// Returns error if no LUKS volumes are found.
func DetectVolume(ctx context.Context) (*Volume, error) {
	volumes, err := DetectAllVolumes(ctx)
	if err != nil {
		return nil, err
	}
	if len(volumes) == 0 {
		return nil, fmt.Errorf("no LUKS-encrypted volumes detected on this device")
	}
	if len(volumes) == 1 {
		return &volumes[0], nil
	}

	// Prefer volume with /home mounted
	for i := range volumes {
		if volumes[i].MountPoint == "/home" {
			return &volumes[i], nil
		}
	}
	// Fall back to volume with / mounted
	for i := range volumes {
		if volumes[i].MountPoint == "/" {
			return &volumes[i], nil
		}
	}
	// Last resort: first found
	return &volumes[0], nil
}

// DetectAllVolumes returns all LUKS-encrypted volumes on the system.
func DetectAllVolumes(ctx context.Context) ([]Volume, error) {
	result, err := exec.Run(ctx, "lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT")
	if err != nil {
		return nil, fmt.Errorf("lsblk failed: %w", err)
	}

	var output lsblkOutput
	if err := json.Unmarshal([]byte(result.Stdout), &output); err != nil {
		return nil, fmt.Errorf("failed to parse lsblk output: %w", err)
	}

	var volumes []Volume
	findLuksVolumes(&output.BlockDevices, &volumes)
	return volumes, nil
}

func findLuksVolumes(devices *[]lsblkDevice, volumes *[]Volume) {
	for _, dev := range *devices {
		fstype := ""
		if dev.FSType != nil {
			fstype = *dev.FSType
		}

		if fstype == "crypto_LUKS" {
			vol := Volume{
				DevicePath: "/dev/" + dev.Name,
			}
			// Check children for unlocked mapper device
			for _, child := range dev.Children {
				if child.Type == "crypt" {
					vol.MapperName = child.Name
					if child.MountPoint != nil && *child.MountPoint != "" {
						vol.MountPoint = *child.MountPoint
					}
					// Check children of crypt device (e.g., LVM on LUKS)
					for _, grandchild := range child.Children {
						if grandchild.MountPoint != nil && *grandchild.MountPoint != "" {
							vol.MountPoint = *grandchild.MountPoint
						}
					}
				}
			}
			*volumes = append(*volumes, vol)
		}

		// Recurse into children
		if len(dev.Children) > 0 {
			findLuksVolumes(&dev.Children, volumes)
		}
	}
}
