package exec

import (
	"regexp"
	"strings"
)

// ValidEnvVarName matches safe environment variable names (letters, digits, underscore).
var ValidEnvVarName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// BlockedEnvVars are environment variable names that must never be overridden
// because they can hijack process execution (library injection, path manipulation).
var BlockedEnvVars = map[string]bool{
	"LD_PRELOAD":      true,
	"LD_LIBRARY_PATH": true,
	"LD_AUDIT":        true,
	"LD_DEBUG":        true,
	"LD_PROFILE":      true,
	"PATH":            true,
	"IFS":             true,
	"ENV":             true,
	"BASH_ENV":        true,
	"CDPATH":          true,
	"GLOBIGNORE":      true,
	"BASH_FUNC_":      true,
}

// IsAllowedEnvVar returns true if the environment variable name is safe to set.
func IsAllowedEnvVar(name string) bool {
	if !ValidEnvVarName.MatchString(name) {
		return false
	}
	upper := strings.ToUpper(name)
	if BlockedEnvVars[upper] {
		return false
	}
	// Block LD_* and BASH_FUNC_* prefixes
	if strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "BASH_FUNC_") {
		return false
	}
	return true
}
