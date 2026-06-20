package service

import (
	"fmt"
	"path"
	"strings"
)

// ErrUnsafeUnitContent is returned by WriteUnit when the unit body carries a
// directive that would turn the agent into a root persistence / dropper
// primitive. A unit file written to /etc/systemd/system is executed by PID 1 as
// root, so its content is as privileged as the executables it names — the
// content policy below is the gate that keeps an attacker-supplied unit from
// running `curl | sh`, preloading a hostile library into every service, or
// executing a payload out of a world-writable directory.
var ErrUnsafeUnitContent = fmt.Errorf("unsafe systemd unit content")

// execDirectives are the unit keys whose value is a command line systemd runs
// as the service's process. Matched case-insensitively (systemd directive keys
// are case-sensitive in practice but we normalise defensively so a "execstart="
// can't slip a payload past the policy).
var execDirectives = map[string]struct{}{
	"execstart":     {},
	"execstartpre":  {},
	"execstartpost": {},
	"execstop":      {},
	"execstoppost":  {},
	"execreload":    {},
	"execcondition": {},
}

// shellInterpreters are basenames that, when invoked with -c, run an arbitrary
// inline command string — the classic `sh -c 'curl … | sh'` dropper and the
// `sh -c 'echo … >> /root/.ssh/authorized_keys'` persistence writer. A unit that
// shells out this way is refused; a unit must name the real executable directly.
var shellInterpreters = map[string]struct{}{
	"sh": {}, "bash": {}, "dash": {}, "zsh": {}, "ksh": {}, "ash": {}, "busybox": {},
}

// untrustedExecPrefixes are directories any local user can write to. An Exec*
// directive that runs a binary out of one of these is refused: the binary's
// integrity cannot be trusted, so it is a privilege-escalation dropper vector.
var untrustedExecPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// dangerousEnvVars are environment variables that redirect the dynamic linker
// to attacker-controlled code in every process the unit (and anything it execs)
// spawns. Setting any of them through a unit is a code-injection vector and is
// refused regardless of the value.
var dangerousEnvVars = map[string]struct{}{
	"LD_PRELOAD":      {},
	"LD_LIBRARY_PATH": {},
	"LD_AUDIT":        {},
}

// validateUnitContent enforces the unit-file content policy. It is the gate
// WriteUnit calls BEFORE the root-owned unit file is created, so a rejected unit
// never reaches the filesystem. The checks are deny-by-intent: an Exec* that
// shells out, runs from a world-writable directory, or an Environment that
// injects a dynamic-linker override fails closed.
func validateUnitContent(content string) error {
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue // section header ("[Service]") or malformed — not a directive
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		value := strings.TrimSpace(line[eq+1:])

		if _, isExec := execDirectives[key]; isExec {
			if err := validateExecLine(key, value); err != nil {
				return err
			}
			continue
		}
		if key == "environment" || key == "environmentfile" {
			if err := validateEnvLine(value); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateExecLine rejects an Exec* command line that shells out to an inline
// command or runs a binary from a world-writable directory.
func validateExecLine(key, value string) error {
	// Strip systemd's Exec* special prefixes (any combination/order of these
	// characters precedes the executable path): '-' ignore-failure, '@' argv0,
	// '+' full-privilege, '!' / '!!' ambient-capability variants, ':' no env
	// expansion. Stripping them exposes the real executable token.
	cmd := strings.TrimLeft(value, "-@+!:")
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil // empty Exec* (resets the list) — nothing to run
	}
	fields := strings.Fields(cmd)
	exe := fields[0]
	base := path.Base(exe)

	// A shell interpreter invoked with -c runs an arbitrary inline command — the
	// curl|sh dropper and the authorized_keys writer both take this shape.
	if _, isShell := shellInterpreters[base]; isShell {
		for _, arg := range fields[1:] {
			if arg == "-c" || strings.HasPrefix(arg, "-c") {
				return fmt.Errorf("%w: %s shells out via %q -c (inline command execution)", ErrUnsafeUnitContent, key, base)
			}
		}
	}

	// A binary executed out of a world-writable directory cannot be trusted.
	for _, prefix := range untrustedExecPrefixes {
		if strings.HasPrefix(exe, prefix) {
			return fmt.Errorf("%w: %s runs %q from a world-writable directory", ErrUnsafeUnitContent, key, exe)
		}
	}
	return nil
}

// validateEnvLine rejects an Environment/EnvironmentFile directive that sets a
// dynamic-linker override (LD_PRELOAD and friends).
func validateEnvLine(value string) error {
	// A single Environment= line may set several VAR=VAL pairs separated by
	// whitespace; inspect each.
	for _, pair := range strings.Fields(value) {
		eq := strings.IndexByte(pair, '=')
		name := pair
		if eq >= 0 {
			name = pair[:eq]
		}
		name = strings.Trim(strings.TrimSpace(name), `"'`)
		if _, bad := dangerousEnvVars[strings.ToUpper(name)]; bad {
			return fmt.Errorf("%w: sets %s, a dynamic-linker override", ErrUnsafeUnitContent, name)
		}
	}
	return nil
}
