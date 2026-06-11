package notify

import (
	"slices"
	"testing"
)

// desktopNotifyArgv must end with "--", title, message so a notification
// title or body beginning with "-" is treated as text, not parsed as a
// notify-send option (-i icon, -h hint, -c category, …). The runuser
// wrapper keeps its own "--"; there must be two markers in the argv.
func TestDesktopNotifyArgv_SeparatesTitleAndBody(t *testing.T) {
	argv := desktopNotifyArgv("unix:path=/run/user/1000/bus", "alice", "-h evil", "-i /tmp/x")

	// The user-controlled title/body are the final two elements, preceded
	// immediately by the end-of-options marker.
	n := len(argv)
	if n < 3 || argv[n-3] != "--" || argv[n-2] != "-h evil" || argv[n-1] != "-i /tmp/x" {
		t.Fatalf("argv tail = %v, want [.. -- '-h evil' '-i /tmp/x']", argv[max(0, n-3):])
	}

	// Two markers: one ends runuser's options, one ends notify-send's.
	if c := slices.IndexFunc(argv, func(s string) bool { return s == "--" }); c < 0 {
		t.Fatal("missing end-of-options marker")
	}
	markers := 0
	for _, a := range argv {
		if a == "--" {
			markers++
		}
	}
	if markers != 2 {
		t.Errorf("found %d '--' markers, want 2 (runuser + notify-send)", markers)
	}
}
