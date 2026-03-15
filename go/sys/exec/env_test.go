package exec

import "testing"

func TestIsAllowedEnvVar_Safe(t *testing.T) {
	allowed := []string{
		"MY_VAR",
		"HOME",
		"USER",
		"LANG",
		"LC_ALL",
		"TZ",
		"DISPLAY",
		"XDG_RUNTIME_DIR",
		"TERM",
		"SHELL",
		"GO111MODULE",
		"GOPATH",
		"NODE_ENV",
		"DATABASE_URL",
		"PORT",
		"lower_case",
		"_LEADING_UNDERSCORE",
		"A",
		"var123",
	}

	for _, name := range allowed {
		if !IsAllowedEnvVar(name) {
			t.Errorf("IsAllowedEnvVar(%q) = false, want true", name)
		}
	}
}

func TestIsAllowedEnvVar_Blocked(t *testing.T) {
	blocked := []string{
		// Explicit blocklist
		"LD_PRELOAD",
		"LD_LIBRARY_PATH",
		"LD_AUDIT",
		"LD_DEBUG",
		"LD_PROFILE",
		"PATH",
		"IFS",
		"ENV",
		"BASH_ENV",
		"CDPATH",
		"GLOBIGNORE",
		"BASH_FUNC_",
		// Case insensitive
		"ld_preload",
		"Ld_Preload",
		"path",
		"Path",
		"ifs",
		// LD_* prefix catch-all
		"LD_WHATEVER",
		"LD_NEW_ATTACK",
		"ld_custom",
		// BASH_FUNC_* prefix catch-all
		"BASH_FUNC_exploit",
		"BASH_FUNC_any_function",
		// DYLD_* prefix catch-all (macOS)
		"DYLD_INSERT_LIBRARIES",
		"DYLD_LIBRARY_PATH",
		"dyld_insert_libraries",
		// New blocklist entries
		"GCONV_PATH",
		"HOSTALIASES",
		"RESOLV_HOST_CONF",
		"GETCONF_DIR",
		"NODE_OPTIONS",
		"PYTHONPATH",
		"PERL5OPT",
		"PERL5LIB",
		"RUBYLIB",
	}

	for _, name := range blocked {
		if IsAllowedEnvVar(name) {
			t.Errorf("IsAllowedEnvVar(%q) = true, want false", name)
		}
	}
}

func TestIsAllowedEnvVar_InvalidNames(t *testing.T) {
	invalid := []string{
		"",
		"1STARTS_WITH_DIGIT",
		"HAS SPACE",
		"HAS-DASH",
		"HAS.DOT",
		"HAS=EQUALS",
		"HAS;SEMICOLON",
		"$(whoami)",
		"`whoami`",
		"FOO\nBAR",
		"FOO\tBAR",
	}

	for _, name := range invalid {
		if IsAllowedEnvVar(name) {
			t.Errorf("IsAllowedEnvVar(%q) = true, want false (invalid name)", name)
		}
	}
}

func TestBlockedEnvVars_Completeness(t *testing.T) {
	// Verify the critical security-sensitive env vars are in the blocklist
	critical := []string{
		"LD_PRELOAD",
		"LD_LIBRARY_PATH",
		"PATH",
		"IFS",
		"BASH_ENV",
		"GCONV_PATH",
		"NODE_OPTIONS",
		"HOSTALIASES",
	}

	for _, name := range critical {
		if !BlockedEnvVars[name] {
			t.Errorf("BlockedEnvVars missing critical entry %q", name)
		}
	}
}

func TestValidEnvVarName_Regex(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"A", true},
		{"_A", true},
		{"A1", true},
		{"_", true},
		{"__", true},
		{"a_b_c", true},
		{"ABC123", true},
		{"1ABC", false},
		{"", false},
		{"-abc", false},
		{"a b", false},
		{"a.b", false},
	}

	for _, tt := range tests {
		got := ValidEnvVarName.MatchString(tt.name)
		if got != tt.valid {
			t.Errorf("ValidEnvVarName.MatchString(%q) = %v, want %v", tt.name, got, tt.valid)
		}
	}
}
