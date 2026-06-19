package antivirus

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

func newClam(t *testing.T) (*clamavManager, *exectest.FakeRunner) {
	t.Helper()
	r := exectest.New(exec.Direct)
	m, err := New(ClamAV, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m.(*clamavManager), r
}

func TestNew_NilRunner(t *testing.T) {
	if _, err := New(ClamAV, nil); !errors.Is(err, exec.ErrRunnerRequired) {
		t.Errorf("New(_, nil) error = %v, want ErrRunnerRequired", err)
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	for _, b := range []Backend{0, Backend(-1), Backend(99)} {
		if _, err := New(b, exectest.New(exec.Direct)); !errors.Is(err, ErrUnknownBackend) {
			t.Errorf("New(%d) err = %v, want ErrUnknownBackend", b, err)
		}
	}
}

func TestBackendString(t *testing.T) {
	if ClamAV.String() != "clamav" || Backend(0).String() != "Backend(0)" {
		t.Errorf("String = %q / %q", ClamAV.String(), Backend(0).String())
	}
}

func TestValidatePath(t *testing.T) {
	cases := map[string]bool{"/home": true, "/tmp/x": true, "": false, "-rf": false, "/a\x00b": false}
	for p, valid := range cases {
		err := validatePath(p)
		if valid != (err == nil) {
			t.Errorf("validatePath(%q): err=%v, wantValid=%v", p, err, valid)
		}
	}
}

func TestScan_Clean(t *testing.T) {
	m, r := newClam(t)
	r.Push(exec.Result{ExitCode: 0, Stdout: ""}, nil) // clean
	res, err := m.Scan(context.Background(), "/home")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean() || res.Path != "/home" {
		t.Errorf("res = %+v, want clean for /home", res)
	}
	argv := strings.Join(r.Calls()[0].Args, " ")
	if argv != "-r --no-summary --infected -- /home" || !r.Calls()[0].Escalate {
		t.Errorf("scan argv = %q (escalate=%v)", argv, r.Calls()[0].Escalate)
	}
}

func TestScan_Infected(t *testing.T) {
	m, r := newClam(t)
	// Exit 1 = found (NOT an error).
	r.Push(exec.Result{ExitCode: 1, Stdout: "/home/u/evil.com: Win.Test.EICAR_HDB-1 FOUND\n/home/u/x.bin: Unix.Trojan.Foo-2 FOUND\n"}, nil)
	res, err := m.Scan(context.Background(), "/home")
	if err != nil {
		t.Fatalf("exit 1 (infected) must not be an error: %v", err)
	}
	if res.Clean() || len(res.Infected) != 2 {
		t.Fatalf("infected = %+v, want 2", res.Infected)
	}
	if res.Infected[0] != (Infection{File: "/home/u/evil.com", Signature: "Win.Test.EICAR_HDB-1"}) {
		t.Errorf("infection[0] = %+v", res.Infected[0])
	}
	if res.Infected[1].Signature != "Unix.Trojan.Foo-2" {
		t.Errorf("infection[1] = %+v", res.Infected[1])
	}
}

func TestScan_EngineError(t *testing.T) {
	m, r := newClam(t)
	r.Push(exec.Result{ExitCode: 2, Stderr: "database not found"}, nil) // exit 2 = error
	if _, err := m.Scan(context.Background(), "/home"); err == nil {
		t.Error("exit 2 must be an error")
	}
}

func TestScan_BadPath(t *testing.T) {
	m, r := newClam(t)
	if _, err := m.Scan(context.Background(), "-rf"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("err = %v, want ErrInvalidPath", err)
	}
	if len(r.Calls()) != 0 {
		t.Error("a bad path must run nothing")
	}
}

func TestScan_RunError(t *testing.T) {
	m, r := newClam(t)
	r.Push(exec.Result{}, errors.New("clamscan not found"))
	if _, err := m.Scan(context.Background(), "/home"); err == nil {
		t.Error("a Runner error must surface")
	}
}

func TestUpdateSignatures(t *testing.T) {
	m, r := newClam(t)
	r.Push(exec.Result{ExitCode: 0}, nil)
	if err := m.UpdateSignatures(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Calls()[0].Name != "freshclam" || !r.Calls()[0].Escalate {
		t.Errorf("update call = %+v, want escalated freshclam", r.Calls()[0])
	}
}

func TestUpdateSignatures_Errors(t *testing.T) {
	m, r := newClam(t)
	r.Push(exec.Result{ExitCode: 1, Stderr: "mirror error"}, nil)
	if err := m.UpdateSignatures(context.Background()); err == nil {
		t.Error("a non-zero freshclam exit must error")
	}
	r.Push(exec.Result{}, errors.New("gone"))
	if err := m.UpdateSignatures(context.Background()); err == nil {
		t.Error("a Runner error must surface")
	}
}

func TestVersion(t *testing.T) {
	m, r := newClam(t)
	r.Push(exec.Result{Stdout: "ClamAV 1.0.1/27000/Wed Jun 18 09:00:00 2025\n"}, nil)
	v, err := m.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Engine != "1.0.1" || v.Signature != "27000" {
		t.Errorf("version = %+v, want engine 1.0.1 / sig 27000", v)
	}
	if r.Calls()[0].Escalate {
		t.Error("Version must not escalate")
	}
}

func TestVersion_Errors(t *testing.T) {
	m, r := newClam(t)
	r.Push(exec.Result{ExitCode: 1, Stderr: "x"}, nil)
	if _, err := m.Version(context.Background()); err == nil {
		t.Error("non-zero exit must error")
	}
	r.Push(exec.Result{}, errors.New("gone"))
	if _, err := m.Version(context.Background()); err == nil {
		t.Error("Runner error must surface")
	}
	r.Push(exec.Result{Stdout: "garbage"}, nil)
	if _, err := m.Version(context.Background()); err == nil {
		t.Error("unparseable version must error")
	}
}

func TestParseClamscanVersion(t *testing.T) {
	// Contract: accept ONLY the canonical "ClamAV <engine>/<sig>[/<date>]" line —
	// the literal "ClamAV " prefix is required and BOTH engine and signature must
	// be present and non-empty. The rejection cases are derived from that contract
	// (a version line must carry the prefix + both fields), not from the parser's
	// current behaviour, so an under-specified parser is caught.
	valid := map[string]Version{
		"ClamAV 1.0.1/27000/Wed Jun 18 09:00:00 2025\n": {Engine: "1.0.1", Signature: "27000"},
		"  ClamAV 1.0.1/27000  ":                        {Engine: "1.0.1", Signature: "27000"}, // no date, surrounding whitespace
	}
	for in, want := range valid {
		got, err := parseClamscanVersion(in)
		if err != nil {
			t.Errorf("parseClamscanVersion(%q) unexpected err: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseClamscanVersion(%q) = %+v, want %+v", in, got, want)
		}
	}
	reject := []string{
		"",                   // empty
		"garbage",            // no prefix, no slash
		"1.0.1/27000",        // missing "ClamAV " prefix entirely
		"1.0.1/27000/date",   // missing prefix, otherwise full shape
		"ClamXV 1.0.1/27000", // wrong prefix
		"ClamAV ",            // prefix only, nothing after
		"ClamAV 1.0.1",       // engine but no signature field
		"ClamAV 1.0.1//date", // empty signature
		"ClamAV /27000/date", // empty engine
	}
	for _, in := range reject {
		if v, err := parseClamscanVersion(in); err == nil {
			t.Errorf("parseClamscanVersion(%q) = %+v, want error", in, v)
		}
	}
}

func TestParseClamscanInfected_SkipsNoise(t *testing.T) {
	// Summary/blank lines and malformed FOUND lines are ignored.
	inf := parseClamscanInfected("\n----------- SCAN SUMMARY -----------\nInfected files: 1\nFOUND\nnoColonButEndsWith FOUND\n/a/b: Sig FOUND\n")
	if len(inf) != 1 || inf[0].File != "/a/b" {
		t.Errorf("parsed = %+v, want one /a/b (noise + a FOUND line lacking ': ' skipped)", inf)
	}
}

func TestDetect(t *testing.T) {
	prev := lookPath
	t.Cleanup(func() { lookPath = prev })
	lookPath = func(string) (string, error) { return "", errors.New("no") }
	if got := Detect(context.Background()); len(got) != 0 {
		t.Errorf("Detect (absent) = %v, want empty", got)
	}
	lookPath = func(name string) (string, error) {
		if name == "clamscan" {
			return "/usr/bin/clamscan", nil
		}
		return "", errors.New("no")
	}
	if got := Detect(context.Background()); len(got) != 1 || got[0] != ClamAV {
		t.Errorf("Detect (present) = %v, want [ClamAV]", got)
	}
}
