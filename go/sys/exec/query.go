package exec

import (
	"fmt"
	"strings"

	"github.com/go-cmd/cmd"
)

// Query runs a simple command and returns stdout.
// This is for quick queries that don't need context or detailed error handling.
func Query(name string, args ...string) (string, error) {
	c := cmd.NewCmd(name, args...)
	status := <-c.Start()
	if status.Error != nil {
		return "", status.Error
	}
	if status.Exit != 0 {
		return "", fmt.Errorf("exit code %d", status.Exit)
	}
	return strings.Join(status.Stdout, "\n"), nil
}

// QueryOutput runs a command and returns stdout, exit code, and any error.
// Returns stdout even on non-zero exit for commands where exit code matters.
func QueryOutput(name string, args ...string) (stdout string, exitCode int, err error) {
	c := cmd.NewCmd(name, args...)
	status := <-c.Start()
	return strings.Join(status.Stdout, "\n"), status.Exit, status.Error
}

// Check runs a command and returns true if it succeeds (exit 0, no error).
func Check(name string, args ...string) bool {
	c := cmd.NewCmd(name, args...)
	status := <-c.Start()
	return status.Exit == 0 && status.Error == nil
}

// FormatError formats a command error with stderr output for better diagnostics.
func FormatError(err error, result *Result) string {
	if result != nil && result.Stderr != "" {
		return fmt.Sprintf("%v: %s", err, strings.TrimSpace(result.Stderr))
	}
	return err.Error()
}
