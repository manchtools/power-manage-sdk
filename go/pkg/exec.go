// Privilege dispatch helper for the package-manager backends.
//
// Every Apt/Dnf/Pacman/Zypper/Flatpak/Repair shell-out used to hardcode
// `"sudo", "-n"`, which silently broke the doas backend on hosts that
// configured it via SetPrivilegeBackend. CONTRIBUTING.md (line 71)
// explicitly bans direct `os/exec` use for privileged operations:
//
//	Privileged operations go through `sys/exec.Privileged` —
//	not direct `os/exec`.
//
// runPM routes the privileged path through PrivilegedStreaming (which
// already does absolute-path resolution + backend dispatch + the `-n`
// flag) and the unprivileged path through RunStreaming. Both branches
// support env injection — package backends need DEBIAN_FRONTEND,
// LANG=C, LC_ALL=C — which the simpler `sys/exec.Run` does not.
package pkg

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// readCmd builds an *exec.Cmd for a read-side package-manager query
// (Info / Search / List / Show / version checks / status probes) with
// LANG=C and LC_ALL=C forced so the output parser sees the stable
// English form regardless of the host locale.
//
// The privileged write paths (Install / Remove / Update) go through
// runPM, which already injects the env via PrivilegedStreaming. The
// read paths historically used os/exec directly and would misparse
// localized output (e.g. "Beschreibung:" instead of "Description:")
// on non-English hosts. Use this helper for every read-side shell-out
// from the package backends; the cmd returned is wired to the same
// context the caller provides so timeout / cancel propagate.
func readCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	return c
}

// runPM executes a package-manager command and returns a CommandResult.
// When useSudo is true the command runs through the configured privilege
// backend (sudo or doas, see exec.SetPrivilegeBackend). Both paths share
// the same env / output capture / exit code recording so callers see a
// uniform CommandResult regardless of escalation.
func runPM(ctx context.Context, useSudo bool, name string, args []string, envVars []string) (*CommandResult, error) {
	start := time.Now()

	var (
		res *pmexec.Result
		err error
	)
	if useSudo {
		res, err = pmexec.PrivilegedStreaming(ctx, name, args, envVars, "", nil)
	} else {
		res, err = pmexec.RunStreaming(ctx, name, args, envVars, "", nil)
	}

	result := &CommandResult{Duration: time.Since(start)}
	if res != nil {
		result.Stdout = res.Stdout
		result.Stderr = res.Stderr
		result.ExitCode = res.ExitCode
	}
	result.Success = err == nil
	return result, err
}

// runPMWithStdin is the stdin-bearing companion of runPM. It dispatches
// through PrivilegedWithStdin / RunWithStdin instead of the streaming
// variants (which do not accept stdin).
func runPMWithStdin(ctx context.Context, useSudo bool, stdin string, name string, args ...string) (*CommandResult, error) {
	start := time.Now()
	var reader io.Reader
	if stdin != "" {
		reader = strings.NewReader(stdin)
	}

	var (
		res *pmexec.Result
		err error
	)
	if useSudo {
		res, err = pmexec.PrivilegedWithStdin(ctx, reader, name, args...)
	} else {
		res, err = pmexec.RunWithStdin(ctx, reader, name, args...)
	}

	result := &CommandResult{Duration: time.Since(start)}
	if res != nil {
		result.Stdout = res.Stdout
		result.Stderr = res.Stderr
		result.ExitCode = res.ExitCode
	}
	result.Success = err == nil
	return result, err
}
