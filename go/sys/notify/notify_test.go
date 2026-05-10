package notify

import (
	"reflect"
	"testing"
)

// loginctl(1) emits one line per session for `list-sessions --no-legend`,
// space-separated: SESSION UID USER SEAT TTY. Anything with fewer than
// three fields is junk (blank line, "no sessions" placeholder).
func TestParseLoginctlListSessions(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   []string
	}{
		{
			name:   "empty",
			stdout: "",
			want:   nil,
		},
		{
			name:   "single graphical session",
			stdout: "c1 1000 alice seat0 -",
			want:   []string{"c1"},
		},
		{
			name:   "multiple sessions",
			stdout: "c1 1000 alice seat0 -\nc2 1001 bob seat0 tty3\nc3 1002 carol - -",
			want:   []string{"c1", "c2", "c3"},
		},
		{
			name:   "skips short lines",
			stdout: "c1 1000\n\nc2 1001 bob seat0 -",
			want:   []string{"c2"},
		},
		{
			name:   "trims trailing whitespace",
			stdout: "  c1 1000 alice seat0 -  \n",
			want:   []string{"c1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLoginctlListSessions(tc.stdout)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseLoginctlListSessions(%q) = %v, want %v", tc.stdout, got, tc.want)
			}
		})
	}
}

// `loginctl show-session <id> -p Type -p Name -p User --value` emits one
// value per requested property, in order. We only treat x11 / wayland /
// mir as graphical — every other type (tty, unspecified, …) is dropped.
func TestParseLoginctlShowSession(t *testing.T) {
	cases := []struct {
		name      string
		sessionID string
		stdout    string
		wantOK    bool
		want      session
	}{
		{
			name:      "wayland session",
			sessionID: "c1",
			stdout:    "wayland\nalice\n1000",
			wantOK:    true,
			want:      session{id: "c1", user: "alice", uid: 1000, typ: "wayland"},
		},
		{
			name:      "x11 session",
			sessionID: "c2",
			stdout:    "x11\nbob\n1001",
			wantOK:    true,
			want:      session{id: "c2", user: "bob", uid: 1001, typ: "x11"},
		},
		{
			name:      "mir session",
			sessionID: "c3",
			stdout:    "mir\ncarol\n1002",
			wantOK:    true,
			want:      session{id: "c3", user: "carol", uid: 1002, typ: "mir"},
		},
		{
			name:      "tty session is rejected",
			sessionID: "c4",
			stdout:    "tty\ndave\n1003",
			wantOK:    false,
		},
		{
			name:      "unspecified type is rejected",
			sessionID: "c5",
			stdout:    "\nerin\n1004",
			wantOK:    false,
		},
		{
			name:      "too few lines",
			sessionID: "c6",
			stdout:    "wayland\nfrank",
			wantOK:    false,
		},
		{
			// Malformed UID is now treated as an invalid session
			// because uid=0 (the silent Atoi fallback) would build
			// /run/user/0/bus and either misroute the notification
			// to root's session or get suppressed entirely. CR
			// finding on PR #57.
			name:      "garbage uid is rejected as an invalid session",
			sessionID: "c7",
			stdout:    "x11\ngrace\nnotanint",
			wantOK:    false,
		},
		{
			name:      "trims surrounding whitespace",
			sessionID: "c8",
			stdout:    "  wayland \n  henry  \n  1005  ",
			wantOK:    true,
			want:      session{id: "c8", user: "henry", uid: 1005, typ: "wayland"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseLoginctlShowSession(tc.sessionID, tc.stdout)
			if ok != tc.wantOK {
				t.Fatalf("parseLoginctlShowSession ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got != tc.want {
				t.Errorf("parseLoginctlShowSession = %+v, want %+v", got, tc.want)
			}
		})
	}
}
