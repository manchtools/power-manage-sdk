package firewall

import (
	"errors"
	"testing"
)

// These tests pin audit finding #12 — the cross-backend rule
// validation contract. They run validateRule directly so they don't
// depend on a configured backend (every backend's ApplyRule funnels
// through validateRule first; the wiring is verified by the existing
// firewall_test.go entry-path tests).

func TestValidateRule_AcceptsCanonicalShape(t *testing.T) {
	rule := Rule{
		ID:       "ssh-in",
		Allow:    true,
		Protocol: ProtocolTCP,
		Port:     22,
		Source:   "10.0.0.0/8",
		Dest:     "192.168.1.1",
	}
	if err := validateRule(rule); err != nil {
		t.Fatalf("validateRule(canonical) = %v; want nil", err)
	}
}

func TestValidateRule_RejectsBadID(t *testing.T) {
	for _, id := range []string{
		"",
		"-leading-hyphen",
		"UPPERCASE",
		"contains space",
		"too-long-" + repeat("x", 64),
	} {
		t.Run(id, func(t *testing.T) {
			err := validateRule(Rule{ID: id, Protocol: ProtocolTCP, Port: 22})
			if !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("validateRule(ID=%q) = %v; want ErrInvalidRule", id, err)
			}
		})
	}
}

func TestValidatePort_RangeBoundaries(t *testing.T) {
	// Inside the range.
	for _, p := range []int{0, 1, 22, 443, 65535} {
		t.Run(label("ok", p), func(t *testing.T) {
			if err := validatePort(p); err != nil {
				t.Fatalf("validatePort(%d) = %v; want nil", p, err)
			}
		})
	}
	// Outside the range.
	for _, p := range []int{-1, 65536, 70000, 1 << 31} {
		t.Run(label("reject", p), func(t *testing.T) {
			err := validatePort(p)
			if !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("validatePort(%d) = %v; want ErrInvalidRule", p, err)
			}
		})
	}
}

func TestValidateProtocol_OnlyAcceptsKnownValues(t *testing.T) {
	for _, p := range []Protocol{ProtocolTCP, ProtocolUDP, ProtocolAny} {
		t.Run(string(p)+"/ok", func(t *testing.T) {
			if err := validateProtocol(p); err != nil {
				t.Fatalf("validateProtocol(%q) = %v; want nil", p, err)
			}
		})
	}
	for _, p := range []Protocol{"icmp", "TCP", "TcP", "rm -rf"} {
		t.Run(string(p)+"/reject", func(t *testing.T) {
			err := validateProtocol(p)
			if !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("validateProtocol(%q) = %v; want ErrInvalidRule", p, err)
			}
		})
	}
}

func TestValidateAddr_AcceptsIPAndCIDR(t *testing.T) {
	cases := []struct {
		label string
		addr  string
		want  bool
	}{
		{"empty", "", true},
		{"v4 bare", "10.0.0.1", true},
		{"v4 cidr", "10.0.0.0/8", true},
		{"v6 bare", "2001:db8::1", true},
		{"v6 cidr", "2001:db8::/32", true},
		{"v4-mapped-v6", "::ffff:10.0.0.1", true},
		{"hostname", "example.com", false},
		{"garbage", "not-an-ip", false},
		{"shell-shape", "10.0.0.0/8; rm", false},
		{"out-of-range octet", "10.0.0.999", false},
		{"out-of-range mask", "10.0.0.0/40", false},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			err := validateAddr("source", tc.addr)
			gotOK := err == nil
			if gotOK != tc.want {
				t.Fatalf("validateAddr(%q) ok=%v; want %v (err=%v)", tc.addr, gotOK, tc.want, err)
			}
			if !tc.want && !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("validateAddr(%q) returned %v; want wrapped ErrInvalidRule", tc.addr, err)
			}
		})
	}
}

// TestValidateRule_BackendIndependentParity proves the cross-backend
// validator catches every class the audit called out — port range,
// protocol enum, source/dest address shape — before backend dispatch.
// If validateRule grows a new gap later, this table is where the new
// row goes.
func TestValidateRule_BackendIndependentParity(t *testing.T) {
	base := Rule{ID: "ok", Allow: true, Protocol: ProtocolTCP, Port: 22}

	cases := []struct {
		label string
		rule  Rule
	}{
		{"port over 65535", Rule{ID: "ok", Protocol: ProtocolTCP, Port: 70000}},
		{"port negative", Rule{ID: "ok", Protocol: ProtocolTCP, Port: -1}},
		{"protocol garbage", Rule{ID: "ok", Protocol: "icmp", Port: 22}},
		{"source garbage", Rule{ID: "ok", Protocol: ProtocolTCP, Port: 22, Source: "not-an-ip"}},
		{"dest garbage", Rule{ID: "ok", Protocol: ProtocolTCP, Port: 22, Dest: "evil$(id)"}},
		{"id empty", Rule{ID: "", Protocol: ProtocolTCP, Port: 22}},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			err := validateRule(tc.rule)
			if !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("validateRule(%s) = %v; want ErrInvalidRule", tc.label, err)
			}
		})
	}

	// Sanity-check the base case passes — establishes the table's
	// negatives aren't tripping over an unrelated invariant.
	if err := validateRule(base); err != nil {
		t.Fatalf("validateRule(base) = %v; want nil — base case must not regress", err)
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func label(prefix string, port int) string {
	return prefix + "/port=" + itoa(port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
