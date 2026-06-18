//go:build integration

package antivirus_test

import (
	"context"
	"os/exec"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/antivirus"
	pmexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// READ-ONLY: Detect + Version against a real clamscan if present. No Scan/Update
// (a full scan / signature pull is slow and network-bound).
func TestVersion_Integration(t *testing.T) {
	for _, b := range antivirus.Detect(context.Background()) {
		if b != antivirus.ClamAV {
			t.Errorf("Detect returned unexpected backend %v", b)
		}
	}
	if _, err := exec.LookPath("clamscan"); err != nil {
		t.Skip("clamscan not present")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	m, err := antivirus.New(antivirus.ClamAV, r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v, err := m.Version(context.Background())
	if err != nil {
		t.Fatalf("Version against real clamscan: %v", err)
	}
	if v.Engine == "" {
		t.Errorf("Version().Engine empty: %+v", v)
	}
}
