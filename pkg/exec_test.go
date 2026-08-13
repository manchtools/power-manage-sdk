package pkg

import (
	"context"
	"errors"
	"io"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

func TestRunRead_BuildsUnprivilegedCommand(t *testing.T) {
	f := newFake()
	ok(f, "stdout-here")
	res, err := runRead(context.Background(), f, "apt", "search", "vim")
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "stdout-here" {
		t.Errorf("stdout = %q", res.Stdout)
	}
	c := f.Calls()[0]
	if c.Name != "apt" || argv(c) != "apt search vim" {
		t.Errorf("argv = %q", argv(c))
	}
	if c.Escalate {
		t.Error("reads must not escalate")
	}
	// Locale stability is the Runner's invariant (TestRunner_ForcesDeterministicEnv),
	// not a per-command flag — nothing to assert on the Command here.
}

func TestRunRead_PropagatesExecError(t *testing.T) {
	f := newFake()
	f.Push(pmexec.Result{}, errors.New("binary not found"))
	if _, err := runRead(context.Background(), f, "apt", "--version"); err == nil {
		t.Fatal("want exec error")
	}
}

func TestRunPriv_EscalatesAndCarriesEnv(t *testing.T) {
	f := newFake()
	ok(f, "")
	if _, err := runPriv(context.Background(), f, true, []string{"DEBIAN_FRONTEND=noninteractive"}, "apt", "install", "-y", "vim"); err != nil {
		t.Fatal(err)
	}
	c := f.Calls()[0]
	if !c.Escalate {
		t.Error("runPriv(escalate=true) must set Escalate")
	}
	if len(c.Env) != 1 || c.Env[0] != "DEBIAN_FRONTEND=noninteractive" {
		t.Errorf("env = %v", c.Env)
	}
}

func TestRunPriv_NoEscalateForUserScope(t *testing.T) {
	f := newFake()
	ok(f, "")
	if _, err := runPriv(context.Background(), f, false, nil, "flatpak", "update", "--user"); err != nil {
		t.Fatal(err)
	}
	if f.Calls()[0].Escalate {
		t.Error("runPriv(escalate=false) must NOT set Escalate")
	}
}

func TestRunPrivStdin(t *testing.T) {
	t.Run("with stdin", func(t *testing.T) {
		f := newFake()
		ok(f, "")
		if _, err := runPrivStdin(context.Background(), f, true, nil, "new config\n", "tee", "/etc/pacman.conf"); err != nil {
			t.Fatal(err)
		}
		c := f.Calls()[0]
		if c.Stdin == nil {
			t.Fatal("stdin must be set when content is non-empty")
		}
		b, _ := io.ReadAll(c.Stdin)
		if string(b) != "new config\n" {
			t.Errorf("stdin = %q", b)
		}
		if !c.Escalate {
			t.Error("write must escalate")
		}
	})
	t.Run("empty stdin sends nil reader", func(t *testing.T) {
		f := newFake()
		ok(f, "")
		if _, err := runPrivStdin(context.Background(), f, true, nil, "", "tee", "/x"); err != nil {
			t.Fatal(err)
		}
		if f.Calls()[0].Stdin != nil {
			t.Error("empty stdin must leave Command.Stdin nil")
		}
	})
}

func TestReadOut(t *testing.T) {
	t.Run("clean exit returns stdout", func(t *testing.T) {
		f := newFake()
		ok(f, "the output")
		out, err := readOut(context.Background(), f, "rpm", "-qa")
		if err != nil || out != "the output" {
			t.Fatalf("out=%q err=%v", out, err)
		}
	})
	t.Run("non-zero exit is a CommandError", func(t *testing.T) {
		f := newFake()
		f.Push(pmexec.Result{ExitCode: 2, Stderr: "no such file"}, nil)
		_, err := readOut(context.Background(), f, "dpkg-query", "-W", "ghost")
		var ce *pmexec.CommandError
		if !errors.As(err, &ce) {
			t.Fatalf("err = %v, want *exec.CommandError", err)
		}
		if ce.ExitCode != 2 || ce.Stderr != "no such file" || ce.Name != "dpkg-query" {
			t.Errorf("CommandError = %+v", ce)
		}
	})
	t.Run("exec error is propagated raw", func(t *testing.T) {
		f := newFake()
		f.Push(pmexec.Result{}, errors.New("permission denied"))
		if _, err := readOut(context.Background(), f, "rpm", "-qa"); err == nil {
			t.Fatal("want exec error")
		}
	})
}

func TestAsCommandError(t *testing.T) {
	if err := asCommandError("apt", pmexec.Result{ExitCode: 0}); err != nil {
		t.Errorf("exit 0 must be nil, got %v", err)
	}
	err := asCommandError("apt", pmexec.Result{ExitCode: 100, Stderr: "boom"})
	var ce *pmexec.CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 100 || ce.Name != "apt" || ce.Stderr != "boom" {
		t.Errorf("CommandError = %+v (err=%v)", ce, err)
	}
}

func TestCountNonEmptyLines(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"\n\n\n", 0},
		{"a\nb\nc\n", 3},
		{"a\n\n  \nb\n", 2},
		{"only-one", 1},
		{"   \t  ", 0},
	}
	for _, c := range cases {
		if got := countNonEmptyLines(c.in); got != c.want {
			t.Errorf("countNonEmptyLines(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestParseSizeWithUnits_RejectsNonFiniteAndOutOfRange pins the numeric domain
// of the shared size parser.
//
// strconv.ParseFloat happily accepts "NaN", "Inf", "+Inf" and "-Inf", and a
// finite-but-huge mantissa like "1e308" overflows to +Inf once the unit
// multiplier is applied. Converting any of those to int64 is
// implementation-defined in Go — the result is not merely wrong, it is not
// specified — so a package manager emitting junk (or a crafted local .deb/.rpm
// name) could put an arbitrary value into Package.Size. A negative size is
// equally meaningless for a package.
//
// All of them must take the same honest exit the parser already has for
// unparseable text: (0, false), leaving the caller to decide.
func TestParseSizeWithUnits_RejectsNonFiniteAndOutOfRange(t *testing.T) {
	units := []sizeUnit{
		{" KiB", 1024},
		{" MiB", 1024 * 1024},
		{" B", 1},
	}
	for _, in := range []string{
		"NaN MiB",   // ParseFloat accepts NaN
		"nan B",     // and it is case-insensitive
		"+Inf B",    // as are the infinities
		"-Inf B",    //
		"Inf MiB",   //
		"1e308 B",   // finite, but far beyond int64
		"1e308 MiB", // finite input, +Inf after the multiplier
		"-5 MiB",    // negative size
		"-1 B",      //
	} {
		if got, ok := parseSizeWithUnits(in, units); ok {
			t.Errorf("parseSizeWithUnits(%q) = (%d, true), want (0, false): a non-finite, negative or out-of-range size must be reported, not converted", in, got)
		} else if got != 0 {
			t.Errorf("parseSizeWithUnits(%q) failed but returned %d, want 0", in, got)
		}
	}

	// Positive control: the largest value that still fits must survive, so the
	// range guard cannot be satisfied by simply rejecting everything big.
	if got, ok := parseSizeWithUnits("8000000000 B", units); !ok || got != 8000000000 {
		t.Errorf("parseSizeWithUnits(8000000000 B) = (%d, %v), want (8000000000, true)", got, ok)
	}
}
