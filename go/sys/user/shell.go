package user

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrInvalidShell is returned by the login-shell validators when a shell
// value is unsafe to pass to `useradd/usermod -s`.
var ErrInvalidShell = errors.New("invalid login shell")

// loginShellsFile is the system allowlist of valid login shells. A package
// var so tests can point it at a fixture; production reads /etc/shells.
var loginShellsFile = "/etc/shells"

// nonLoginShells are the conventional "disable interactive login" targets.
// They are accepted even when /etc/shells omits them (several distros do),
// because setting an account to a non-login shell is a security-positive
// operation, not a risk.
var nonLoginShells = map[string]bool{
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/usr/bin/nologin":  true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
}

// ValidateLoginShellSyntax is the host-independent half of login-shell
// validation: the shell must be a non-empty, absolute, canonical path with
// no control characters (and therefore no flag shape — a "/"-prefixed path
// can't begin with "-"). It is safe to run anywhere, including a control
// server pre-validating a user profile before dispatching it to an agent.
func ValidateLoginShellSyntax(shell string) error {
	if shell == "" {
		return fmt.Errorf("%w: shell is empty", ErrInvalidShell)
	}
	if strings.ContainsAny(shell, "\x00\n\r\t") {
		return fmt.Errorf("%w: shell contains control characters", ErrInvalidShell)
	}
	if !filepath.IsAbs(shell) {
		return fmt.Errorf("%w: shell %q must be an absolute path", ErrInvalidShell, shell)
	}
	if filepath.Clean(shell) != shell {
		return fmt.Errorf("%w: shell %q is not canonical", ErrInvalidShell, shell)
	}
	return nil
}

// ValidateLoginShell is the full check the agent runs before
// `useradd/usermod -s <shell>`. In addition to ValidateLoginShellSyntax it
// requires the shell to be listed in /etc/shells (the canonical system
// allowlist) or to be a recognized non-login shell. usermod itself does
// NOT enforce /etc/shells, so without this an operator who can drive a
// user action could set any account's login shell to an arbitrary binary.
//
// Fails closed: if /etc/shells cannot be read, only the hardcoded
// non-login set is admitted — a normal shell is rejected rather than
// allowed through unverified.
func ValidateLoginShell(shell string) error {
	if err := ValidateLoginShellSyntax(shell); err != nil {
		return err
	}
	if nonLoginShells[shell] {
		return nil
	}
	allowed, err := readLoginShells(loginShellsFile)
	if err != nil {
		return fmt.Errorf("%w: cannot verify %q against %s: %v", ErrInvalidShell, shell, loginShellsFile, err)
	}
	if !allowed[shell] {
		return fmt.Errorf("%w: %q is not listed in %s", ErrInvalidShell, shell, loginShellsFile)
	}
	return nil
}

// readLoginShells parses an /etc/shells-format file into a set of absolute
// shell paths, ignoring blank lines and `#` comments.
func readLoginShells(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	shells := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		shells[line] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return shells, nil
}
