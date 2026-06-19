package terminal

import "testing"

func TestTTYUsername(t *testing.T) {
	cases := map[string]string{
		"pdotterer": "pm-tty-pdotterer",
		"alice":     "pm-tty-alice",
		"":          "pm-tty-",
	}
	for in, want := range cases {
		if got := TTYUsername(in); got != want {
			t.Errorf("TTYUsername(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTTYUID_Default(t *testing.T) {
	if got := TTYUID(1000, DefaultUIDOffset); got != 101000 {
		t.Errorf("TTYUID(1000, default) = %d, want 101000", got)
	}
	if got := TTYUID(99999, DefaultUIDOffset); got != 199999 {
		t.Errorf("TTYUID(99999, default) = %d, want 199999", got)
	}
}

func TestOriginalUID_Default(t *testing.T) {
	if got := OriginalUID(101000, DefaultUIDOffset); got != 1000 {
		t.Errorf("OriginalUID(101000, default) = %d, want 1000", got)
	}
}

func TestUIDRoundTrip(t *testing.T) {
	for _, uid := range []int{1000, 1001, 50000, 99999} {
		tty := TTYUID(uid, DefaultUIDOffset)
		back := OriginalUID(tty, DefaultUIDOffset)
		if back != uid {
			t.Errorf("round-trip uid=%d: tty=%d, back=%d", uid, tty, back)
		}
	}
}

func TestUIDRoundTrip_CustomOffset(t *testing.T) {
	const offset = 200000
	for _, uid := range []int{1000, 5000, 99999} {
		tty := TTYUID(uid, offset)
		if tty != uid+offset {
			t.Errorf("TTYUID(%d, %d) = %d, want %d", uid, offset, tty, uid+offset)
		}
		if back := OriginalUID(tty, offset); back != uid {
			t.Errorf("OriginalUID round-trip with offset=%d: uid=%d back=%d", offset, uid, back)
		}
	}
}

// TestNoUIDOverlap_DefaultOffset documents the no-overlap invariant
// claimed in issue #16: regular UIDs 1000–99999 map to TTY UIDs
// 101000–199999, so no real user can collide with a TTY user.
func TestNoUIDOverlap_DefaultOffset(t *testing.T) {
	const minRegular, maxRegular = 1000, 99999
	minTTY := TTYUID(minRegular, DefaultUIDOffset)
	maxTTY := TTYUID(maxRegular, DefaultUIDOffset)
	if minTTY <= maxRegular {
		t.Errorf("TTY UID range starts at %d, overlaps regular range max %d", minTTY, maxRegular)
	}
	if minTTY != 101000 || maxTTY != 199999 {
		t.Errorf("TTY UID range = [%d, %d], want [101000, 199999]", minTTY, maxTTY)
	}
}
