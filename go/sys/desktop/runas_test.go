package desktop

import (
	"context"
	"strings"
	"testing"
)

func TestRunAsCommand_RequiresName(t *testing.T) {
	s := Session{Username: "alice", UID: 1000, Home: "/home/alice"}
	if _, err := RunAsCommand(context.Background(), s, nil, ""); err == nil {
		t.Fatal("expected error for empty name — caller bug, runuser would fail with a confusing message")
	}
}

func TestRunAsCommand_RequiresUsername(t *testing.T) {
	s := Session{UID: 1000, Home: "/home/alice"}
	if _, err := RunAsCommand(context.Background(), s, nil, "/bin/true"); err == nil {
		t.Fatal("expected error for session with empty Username — would silently run as the agent's own UID")
	}
}

func TestRunAsCommand_BuildsRunuserInvocation(t *testing.T) {
	s := Session{
		Username:   "alice",
		UID:        1000,
		Home:       "/home/alice",
		RuntimeDir: "/run/user/1000",
	}
	cmd, err := RunAsCommand(context.Background(), s, nil, "/usr/bin/flatpak", "--user", "info", "org.example.App")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The wrapper must always go through runuser, never sudo. Pin
	// the binary path so a refactor toward sudo (which involves
	// sudoers policy and audit-log noise) is caught here.
	if cmd.Path != runuserPath {
		t.Errorf("Path: got %q, want %q (runuser is the only acceptable wrapper)", cmd.Path, runuserPath)
	}

	wantArgs := []string{runuserPath, "-u", "alice", "--", "/usr/bin/flatpak", "--user", "info", "org.example.App"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("Args length: got %d, want %d (got=%v)", len(cmd.Args), len(wantArgs), cmd.Args)
	}
	for i, want := range wantArgs {
		if cmd.Args[i] != want {
			t.Errorf("Args[%d]: got %q, want %q", i, cmd.Args[i], want)
		}
	}

	// Working dir must be the user's home so relative-path
	// commands (e.g. `flatpak --user install some-bundle.flatpak`
	// when bundle is in $HOME) resolve consistently across users.
	if cmd.Dir != "/home/alice" {
		t.Errorf("Dir: got %q, want %q", cmd.Dir, "/home/alice")
	}
}

func TestRunAsCommand_EnvIsolatesAgentEnvironment(t *testing.T) {
	s := Session{
		Username:   "alice",
		UID:        1000,
		Home:       "/home/alice",
		RuntimeDir: "/run/user/1000",
	}
	cmd, err := RunAsCommand(context.Background(), s, []string{"PATH=/usr/bin:/bin", "FLATPAK_USER_DIR=/foo"}, "/bin/true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Critical: cmd.Env REPLACES the inherited env wholesale —
	// LD_PRELOAD, LD_LIBRARY_PATH, GOROOT, etc. from the agent
	// process must NOT leak into the user-scoped command.
	envSet := make(map[string]string, len(cmd.Env))
	for _, e := range cmd.Env {
		eq := strings.IndexByte(e, '=')
		if eq <= 0 {
			continue
		}
		envSet[e[:eq]] = e[eq+1:]
	}

	must := map[string]string{
		"HOME":                     "/home/alice",
		"USER":                     "alice",
		"LOGNAME":                  "alice",
		"XDG_RUNTIME_DIR":          "/run/user/1000",
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
		"PATH":                     "/usr/bin:/bin",
		"FLATPAK_USER_DIR":         "/foo",
	}
	for k, want := range must {
		if got := envSet[k]; got != want {
			t.Errorf("env[%q]: got %q, want %q\nfull env: %v", k, got, want, cmd.Env)
		}
	}

	// Negative coverage: any one of these would indicate the
	// inherit-then-override pattern crept back in. Pinned because
	// LD_* leaking into a user-scoped command opens an obvious
	// privilege-escalation gap.
	for _, leaked := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "GOROOT", "GOPATH"} {
		if _, present := envSet[leaked]; present {
			t.Errorf("agent env %q must not leak into user-scoped command (env=%v)", leaked, cmd.Env)
		}
	}
}

func TestRunAsCommand_ExtraEnvWinsOnDuplicateKey(t *testing.T) {
	// Pin Go's exec.Cmd contract: when cmd.Env contains duplicate
	// keys, the *last* occurrence wins. Our wrapper appends extraEnv
	// after EnvFor, so an extraEnv override (e.g. a custom HOME for
	// a specific action) reliably beats the desktop default.
	s := Session{Username: "alice", UID: 1000, Home: "/home/alice", RuntimeDir: "/run/user/1000"}
	cmd, err := RunAsCommand(context.Background(), s, []string{"HOME=/var/empty"}, "/bin/true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var lastHome string
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "HOME=") {
			lastHome = e
		}
	}
	if lastHome != "HOME=/var/empty" {
		t.Errorf("last HOME entry: got %q, want %q (extraEnv must win on duplicate keys)", lastHome, "HOME=/var/empty")
	}
}
