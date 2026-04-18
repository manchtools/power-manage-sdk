package service

import "testing"

// TestValidateUnitNameSystemd locks down the unit-name regex against
// the edge cases that have been tweaked over multiple CodeRabbit
// review rounds on PR #32. Future refactors that silently re-break
// any of these cases should fail loudly.
//
// The rules (see the comment on validSystemdUnitName):
//
//   * Leading '-' is ALLOWED. systemd has real unit names that start
//     with '-' (e.g. "-.mount", the root mount). Flag-injection at
//     the argv level is prevented by the "--" separator on every
//     systemctl call, not by the regex.
//   * Leading '.' is REJECTED. Dot-prefixed names aren't valid
//     systemd unit names and would look like hidden files.
//   * `\xHH` hex-escape sequences are ACCEPTED at any position so
//     names produced by systemd-escape(1) for paths or reserved
//     characters survive validation.
//   * Suffixes cover every unit type systemd recognises, including
//     the auto-generated .device units for hardware.
func TestValidateUnitNameSystemd(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool // true = valid, false = rejected
	}{
		// --- Plain valid units ---
		{"simple service", "nginx.service", true},
		{"service with dash", "my-service.service", true},
		{"service with underscore", "my_service.service", true},
		{"service with dot-in-name", "my.app.service", true},
		{"service with @", "ssh@host.service", true},
		{"service with colon", "foo:bar.service", true},
		{"socket", "docker.socket", true},
		{"timer", "logrotate.timer", true},
		{"target", "multi-user.target", true},
		{"path", "cups.path", true},
		{"slice", "user.slice", true},
		{"scope", "session.scope", true},
		{"swap unit", "dev-sda2.swap", true},
		{"mount unit", "home.mount", true},
		{"automount unit", "proc-sys-fs-binfmt_misc.automount", true},

		// --- Device units (added in a CR round) ---
		{"device unit with dash", "dev-sda.device", true},
		{"device unit with @", "sys-subsystem-net-devices-eth0.device", true},

		// --- Leading '-' (allowed, needed for -.mount) ---
		{"root mount", "-.mount", true},
		{"leading dash service", "-hidden.service", true},

		// --- Systemd-escaped hex sequences ---
		{"escaped hyphen mid-name", `srv-data\x2dbackup.mount`, true},
		{"escaped space", `my\x20file.path`, true},
		{"escaped char at start", `\x2etmp.path`, true},

		// --- Rejections ---
		{"leading dot", ".hidden.service", false},
		{"missing suffix", "nginx", false},
		{"unknown suffix", "nginx.unknown", false},
		{"empty", "", false},
		{"just a dot", ".", false},
		{"just suffix", ".service", false},
		{"malformed escape missing hex", `foo\xZZ.service`, false},
		{"malformed escape too short", `foo\x2.service`, false},
		{"whitespace", "foo bar.service", false},
		{"path traversal slash", "../../etc/shadow.service", false},
		{"newline injection", "foo\n.service", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validSystemdUnitName.MatchString(tc.input)
			if got != tc.want {
				t.Errorf("validSystemdUnitName.MatchString(%q) = %v, want %v", tc.input, got, tc.want)
			}
			// validateUnitNameSystemd wraps the regex in a descriptive
			// error; make sure the two stay in lockstep.
			err := validateUnitNameSystemd(tc.input)
			if tc.want && err != nil {
				t.Errorf("validateUnitNameSystemd(%q) = %v, want nil", tc.input, err)
			}
			if !tc.want && err == nil {
				t.Errorf("validateUnitNameSystemd(%q) = nil, want error", tc.input)
			}
		})
	}
}
