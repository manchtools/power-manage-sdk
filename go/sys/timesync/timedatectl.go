package timesync

import (
	"context"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// timedatectlManager queries systemd-timesyncd via `timedatectl show`.
type timedatectlManager struct {
	r exec.Runner
}

// Status reports whether NTP sync is enabled and whether the clock is currently
// synchronized. timedatectl does not expose the reference source or offset, so
// those Status fields stay zero (use the Chrony backend for them).
func (m *timedatectlManager) Status(ctx context.Context) (Status, error) {
	out, err := runRead(ctx, m.r, "timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized")
	if err != nil {
		return Status{}, err
	}
	kv := parseKV(out)
	return Status{
		Enabled:      kv["NTP"] == "yes",
		Synchronized: kv["NTPSynchronized"] == "yes",
	}, nil
}

// parseKV parses `key=value` lines (timedatectl show's property form).
func parseKV(s string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}
