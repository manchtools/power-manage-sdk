package exec

import (
	"errors"
	"regexp"
	"strings"
)

// ErrInvalidEnvVar is returned when an env entry in Command.Env is not in the
// canonical KEY=VALUE form. Surfaced as a programmer error so the bad value
// isn't silently dropped before the child runs.
var ErrInvalidEnvVar = errors.New("invalid env entry")

// ErrBlockedEnvVar is returned when an env entry's KEY is on the
// hijack-blocklist (LD_PRELOAD, PATH override, BASH_ENV, GCONV_PATH,
// etc.). Catches CVE-class injections at the SDK boundary so every
// Command.Env passed to the Runner inherits the check in one place.
var ErrBlockedEnvVar = errors.New("env var blocked by hijack-prevention allowlist")

// ErrReservedEnvVar is returned when an env entry tries to set a variable the
// Runner forces for deterministic output (the locale family + NO_COLOR). The SDK
// parses standardized tool output, so a consumer must not be able to change the
// locale/color of a command — these are imposed by the Runner, not negotiable.
var ErrReservedEnvVar = errors.New("env var reserved by the SDK for deterministic output")

// isReservedEnvVar reports whether name is one the Runner forces and a caller
// therefore may not set via Command.Env: the whole LC_* family, LANG, LANGUAGE
// (all neutralised by the forced LC_ALL=C), and NO_COLOR. Case-insensitive.
func isReservedEnvVar(name string) bool {
	upper := strings.ToUpper(name)
	switch upper {
	case "LANG", "LANGUAGE", "NO_COLOR":
		return true
	}
	return strings.HasPrefix(upper, "LC_")
}

// ValidEnvVarName matches safe environment variable names (letters, digits, underscore).
var ValidEnvVarName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// BlockedEnvVars are environment variable names that must never be overridden
// because they can hijack process execution (library injection, path manipulation).
//
// The whole LD_*, BASH_FUNC_*, and DYLD_* families are blocked unconditionally by
// the prefix check in IsAllowedEnvVar, so individual LD_* keys (LD_PRELOAD,
// LD_LIBRARY_PATH, LD_AUDIT, LD_DEBUG, LD_PROFILE) and the BASH_FUNC_ prefix are
// not enumerated here — listing them would only duplicate the prefix rule. This
// map carries the names that have no covering prefix.
var BlockedEnvVars = map[string]bool{
	// glibc iconv module loading (CVE-2021-4034 vector)
	"GCONV_PATH": true,
	// DNS/resolver manipulation
	"HOSTALIASES":      true,
	"RESOLV_HOST_CONF": true,
	// System utility redirection
	"GETCONF_DIR": true,
	// Interpreter library injection
	"NODE_OPTIONS": true,
	"PYTHONPATH":   true,
	"PERL5OPT":     true,
	"PERL5LIB":     true,
	"RUBYLIB":      true,
	// Shell/path manipulation
	"PATH":       true,
	"IFS":        true,
	"ENV":        true,
	"BASH_ENV":   true,
	"CDPATH":     true,
	"GLOBIGNORE": true,
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
	// Block LD_*, BASH_FUNC_*, and DYLD_* (macOS) prefixes
	if strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "BASH_FUNC_") || strings.HasPrefix(upper, "DYLD_") {
		return false
	}
	return true
}
