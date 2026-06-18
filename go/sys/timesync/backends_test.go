package timesync

import (
	"context"
	"errors"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func TestTimedatectl_Status(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: "NTP=yes\nNTPSynchronized=yes\n"}, nil)
	m, _ := New(Timedatectl, r)
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || !st.Synchronized {
		t.Errorf("Status = %+v, want enabled+synchronized", st)
	}
	if argv := r.Calls()[0].Args; argv[0] != "show" || r.Calls()[0].Escalate {
		t.Errorf("argv=%v escalate=%v, want unescalated show", argv, r.Calls()[0].Escalate)
	}
}

func TestTimedatectl_StatusUnsynced(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: "NTP=no\nNTPSynchronized=no\n"}, nil)
	m, _ := New(Timedatectl, r)
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.Synchronized {
		t.Errorf("Status = %+v, want disabled+unsynced", st)
	}
}

func TestTimedatectl_StatusRunError(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{ExitCode: 1, Stderr: "fail"}, nil)
	m, _ := New(Timedatectl, r)
	if _, err := m.Status(context.Background()); err == nil {
		t.Error("Status must surface a run error")
	}
}

func TestParseKV_SkipsMalformed(t *testing.T) {
	kv := parseKV("NTP=yes\n\njustakey\n  NTPSynchronized = no \n")
	if kv["NTP"] != "yes" || kv["NTPSynchronized"] != "no" {
		t.Errorf("parseKV = %v", kv)
	}
	if _, ok := kv["justakey"]; ok {
		t.Error("a line without = must be skipped")
	}
}

// A representative chronyc -c tracking line (14 CSV fields).
const chronyTrackingCSV = `A0F03C2C,203.0.113.1,3,1718000000.0,0.000123456,0.000100,0.000200,1.5,0.1,0.05,0.001,0.002,64,Normal`

func TestChrony_Status(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: chronyTrackingCSV + "\n"}, nil)
	m, _ := New(Chrony, r)
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Synchronized || !st.Enabled {
		t.Errorf("Status = %+v, want synchronized+enabled", st)
	}
	if st.Source != "203.0.113.1" {
		t.Errorf("Source = %q, want 203.0.113.1", st.Source)
	}
	if st.OffsetSeconds != 0.000123456 {
		t.Errorf("OffsetSeconds = %v, want 0.000123456", st.OffsetSeconds)
	}
	if argv := r.Calls()[0].Args; argv[0] != "-c" || argv[1] != "tracking" {
		t.Errorf("argv = %v, want `-c tracking`", argv)
	}
}

func TestChrony_StatusNotSynchronised(t *testing.T) {
	r := exectest.New(exec.Direct)
	// Leap status "Not synchronised" → Synchronized false.
	csv := `00000000,,0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0,Not synchronised`
	r.Push(exec.Result{Stdout: csv}, nil)
	m, _ := New(Chrony, r)
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Synchronized {
		t.Error("a 'Not synchronised' leap status must yield Synchronized=false")
	}
}

func TestChrony_StatusRunError(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{}, errors.New("chronyc gone"))
	m, _ := New(Chrony, r)
	if _, err := m.Status(context.Background()); err == nil {
		t.Error("Status must surface a run error")
	}
}

func TestParseChronyTracking_Errors(t *testing.T) {
	if _, err := parseChronyTracking("   "); err == nil {
		t.Error("empty output must error")
	}
	if _, err := parseChronyTracking("a,b,c"); err == nil {
		t.Error("too-few fields must error")
	}
	// A non-numeric offset is tolerated (stays 0), not a hard error.
	csv := `id,src,3,t,NOTANUMBER,0,0,0,0,0,0,0,64,Normal`
	st, err := parseChronyTracking(csv)
	if err != nil {
		t.Fatalf("non-numeric offset should not be fatal: %v", err)
	}
	if st.OffsetSeconds != 0 {
		t.Errorf("OffsetSeconds = %v, want 0 for an unparseable offset", st.OffsetSeconds)
	}
}
