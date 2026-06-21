package adversary

// Deterministic Simulation Testing (DST), in the style of Turso/Limbo's SQLite
// rewrite: a SEEDED, reproducible engine drives a long randomized sequence of
// capability operations with adversarially-generated inputs, and asserts global
// SAFETY INVARIANTS that must hold for EVERY input — not a fixed list of cases.
// Where the per-package security machines pin specific known attacks, this
// fuzzes the whole argv/secret boundary and catches the attack nobody enumerated.
//
// Reproducibility: the seed is logged and overridable (PM_DST_SEED); a failure
// prints the seed + iteration + operation + raw input so the exact sequence
// replays deterministically. PM_DST_ITERS scales the run.
//
// Invariants checked on every recorded Command:
//   I1  no argument contains a control character — a capability must REJECT a
//       control-bearing operand (config/log injection) before it reaches argv.
//   I2  a flag-shaped operand ("-x") is never a bare argument — it is rejected,
//       or it appears only after a "--" end-of-options separator.
//   I3  an exec.Secret's plaintext never appears in any argument.
// Plus a fault-injection pass: hostile/ malformed host OUTPUT fed to a read path
// must never become an unsafe privileged argument on the follow-up command.

import (
	"context"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
	"github.com/manchtools/power-manage-sdk/sys/dns"
	sdkexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
	"github.com/manchtools/power-manage-sdk/sys/network"
)

const defaultDSTSeed = 0x5d_a_da_7a // a fixed default so CI is deterministic; override with PM_DST_SEED

func dstSeed(t *testing.T) int64 {
	if v := os.Getenv("PM_DST_SEED"); v != "" {
		s, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("PM_DST_SEED=%q is not an int64: %v", v, err)
		}
		return s
	}
	return defaultDSTSeed
}

func dstIters() int {
	if v := os.Getenv("PM_DST_ITERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 4000
}

// adversarialInput builds one operand from a palette that mixes plausibly-valid
// values with every hostile shape the SDK must defend against.
func adversarialInput(r *rand.Rand) string {
	base := func() string {
		n := r.Intn(12) + 1
		const alpha = "abcdefghijklmnopqrstuvwxyz0123456789.-_+"
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		return b.String()
	}
	switch r.Intn(16) {
	case 0:
		return ""
	case 1:
		return base() // plausibly valid
	case 2:
		return "-pmEVIL" + base() // flag-shaped (distinctive marker so it can never
		//                           coincide with a tool's own legitimate flag)
	case 3:
		return "--pmEVIL" + base() // long-flag-shaped, distinctive
	case 4:
		return base() + "\n" + base() // newline injection
	case 5:
		return base() + "\x00evil" // NUL
	case 6:
		return base() + "\t" + base() // tab
	case 7:
		return base() + "; rm -rf /" // shell metacharacters
	case 8:
		return base() + "$(id)" // command substitution
	case 9:
		return base() + "`id`" // backtick
	case 10:
		return base() + "=" + base() // name=version separator
	case 11:
		return base() + "/" + base() // path-ish
	case 12:
		return "../../" + base() // traversal
	case 13:
		return strings.Repeat("a", 200+r.Intn(400)) // overlong
	case 14:
		return "/abs/" + base() // absolute path
	default:
		return base() + string(rune(r.Intn(0x20))) // a random control byte
	}
}

func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// checkArgvInvariants enforces I1 + I2 on a recorded command, given the raw
// adversarial operand the operation was driven with.
func checkArgvInvariants(t *testing.T, seed int64, iter int, op, input string, c sdkexec.Command) {
	t.Helper()
	sepAt := -1
	for i, a := range c.Args {
		if a == sdkexec.EndOfOptions {
			sepAt = i
		}
		// I1: no control character may survive into argv.
		if hasControlByte(a) {
			t.Fatalf("DST seed=%d iter=%d op=%s input=%q: I1 violated — control char reached argv: %s %q",
				seed, iter, op, input, c.Name, c.Args)
		}
		// I2: a flag-shaped argument that is the operand must be after "--".
		if a == input && strings.HasPrefix(a, "-") {
			if sepAt == -1 || sepAt >= i {
				t.Fatalf("DST seed=%d iter=%d op=%s input=%q: I2 violated — flag-shaped operand at argv[%d] with no preceding \"--\": %s %q",
					seed, iter, op, input, i, c.Name, c.Args)
			}
		}
	}
}

// TestDST_ArgvAndSecretInvariants is the property-based core: thousands of
// seeded random operations, each asserting I1/I2/I3.
func TestDST_ArgvAndSecretInvariants(t *testing.T) {
	seed := dstSeed(t)
	iters := dstIters()
	t.Logf("DST argv/secret: seed=%d iters=%d (replay with PM_DST_SEED=%d)", seed, iters, seed)
	r := rand.New(rand.NewSource(seed))
	ctx := context.Background()
	backends := []pkg.Backend{pkg.Apt, pkg.Dnf, pkg.Pacman, pkg.Zypper, pkg.Flatpak}
	totalCmds := 0

	for i := 0; i < iters; i++ {
		input := adversarialInput(r)
		// operand is the raw value the op passes to the tool as a POSITIONAL
		// operand (what I2 protects). "" means the op uses no adversarial
		// positional operand — so a tool's own flag that coincidentally equals
		// `input` (e.g. nmcli's `-f`) is not mistaken for an injected operand.
		operand := input
		fr := exectest.New(sdkexec.Direct)

		switch r.Intn(6) {
		case 0:
			m, _ := pkg.New(backends[r.Intn(len(backends))], fr)
			_, _ = m.Install(ctx, pkg.InstallOptions{}, input)
		case 1:
			m, _ := pkg.New(backends[r.Intn(len(backends))], fr)
			_, _ = m.Remove(ctx, pkg.RemoveOptions{}, input)
		case 2:
			m, _ := pkg.New(backends[r.Intn(len(backends))], fr)
			_, _ = m.InstallLocal(ctx, input, pkg.InstallLocalOptions{})
		case 3:
			m, _ := pkg.New(backends[r.Intn(len(backends))], fr)
			_, _ = m.Search(ctx, input)
		case 4:
			m, _ := pkg.New(backends[r.Intn(len(backends))], fr)
			_, _ = m.Pin(ctx, input)
		case 5:
			// The input is only used (sanitized) as the profile Name — it is not
			// an adversarial positional operand here, so disable the I2 operand
			// check (avoids matching nmcli's own legitimate flags like -f/-t).
			operand = ""
			// I3: a WPA-PSK provisioned via NetworkManager must NEVER appear in
			// any nmcli argument (it goes only to the 0600 keyfile). Drive a
			// random secret through a (possibly adversarial) profile.
			secretVal := "S" + adversarialInput(r) + "Zk9" // make it >=8 so it can validate
			sec, serr := sdkexec.NewSecret(secretVal)
			if serr != nil {
				break // NewSecret rejects newline-bearing secrets — that's a valid rejection
			}
			m, _ := network.New(network.NetworkManager, fr)
			_, _ = m.Apply(ctx, network.Profile{Name: "pm-" + sanitize(input), SSID: "net", AuthType: network.AuthPSK, PSK: sec})
			for _, c := range fr.Calls() {
				for _, a := range c.Args {
					if strings.Contains(a, secretVal) {
						t.Fatalf("DST seed=%d iter=%d op=network.Apply: I3 violated — PSK plaintext in argv: %s %q", seed, i, c.Name, c.Args)
					}
				}
			}
		}

		calls := fr.Calls()
		totalCmds += len(calls)
		for _, c := range calls {
			checkArgvInvariants(t, seed, i, "op", operand, c)
		}
	}
	// matches-zero guard: a driver that rejected EVERY input would pass I1/I2/I3
	// vacuously. Valid inputs must have produced real commands for the invariants
	// to mean anything.
	if totalCmds == 0 {
		t.Fatalf("DST seed=%d: zero commands recorded across %d iterations — the driver is vacuous", seed, iters)
	}
	t.Logf("DST argv/secret: %d commands exercised", totalCmds)
}

// TestDST_FaultInjection_HostileHostOutput is the fault-injection pass: it feeds
// adversarial bytes as the connection name that nmcli (untrusted host output)
// reports back to sys/dns, then asserts that hostile output never becomes a
// privileged argument — dns either rejects it (no follow-up mutation) or proceeds
// only with a clean, validated name. This is the class of attack where a
// compromised host tool tries to inject through what the SDK reads, not what the
// caller passes.
func TestDST_FaultInjection_HostileHostOutput(t *testing.T) {
	seed := dstSeed(t) ^ 0x1
	iters := dstIters() / 2
	t.Logf("DST fault-injection: seed=%d iters=%d", seed, iters)
	r := rand.New(rand.NewSource(seed))
	ctx := context.Background()
	totalCmds := 0

	for i := 0; i < iters; i++ {
		hostile := adversarialInput(r) // the name nmcli reports for the device — UNTRUSTED
		fr := exectest.New(sdkexec.Direct)
		fr.Push(sdkexec.Result{Stdout: hostile + "\n"}, nil) // activeConnection read
		fr.Push(sdkexec.Result{}, nil)                       // modify (only if the name validated)
		fr.Push(sdkexec.Result{}, nil)                       // up
		fr.Push(sdkexec.Result{}, nil)                       // rollback, if up failed
		m, _ := dns.New(dns.NetworkManager, fr)
		_ = m.Apply(ctx, dns.Config{Interface: "wlan0", Nameservers: []string{"10.0.0.53"}})

		calls := fr.Calls()
		totalCmds += len(calls)
		for _, c := range calls {
			// No hostile output may reach argv as a control char or bare flag.
			checkArgvInvariants(t, seed, i, "dns.Apply(hostile-conn-name)", strings.TrimSpace(hostile), c)
			// And a modify/up must never carry a hostile (control-bearing or
			// flag-shaped) connection name — it must have been rejected upstream.
			if c.Name == "nmcli" && len(c.Args) > 0 && (c.Args[0] == "connection") {
				for _, a := range c.Args {
					if a == strings.TrimSpace(hostile) && (hasControlByte(a) || strings.HasPrefix(a, "-")) {
						t.Fatalf("DST seed=%d iter=%d: hostile nmcli output reached a privileged connection command: %q", seed, i, c.Args)
					}
				}
			}
		}
	}
	if totalCmds == 0 {
		t.Fatalf("DST fault-injection seed=%d: zero commands recorded — driver is vacuous", seed)
	}
}

// sanitize keeps the profile Name plausibly valid (Name has its own grammar);
// the adversarial coverage of Name validation lives in the network package tests.
func sanitize(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}
