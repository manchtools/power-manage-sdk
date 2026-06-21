package firewall

import (
	"context"
	"errors"
	"os"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// List must distinguish three states, never collapsing them: a missing table
// (the namespace was never provisioned → explicit os.ErrNotExist), an empty but
// provisioned table (nil slice, no error), and a REAL failure (escalation denied,
// tool error → propagated, never read as "zero managed rules").
func TestNftablesList_NoTableEmptyButRealErrorPropagates(t *testing.T) {
	t.Run("missing table → wrapped os.ErrNotExist", func(t *testing.T) {
		r := exectest.New(pmexec.Direct)
		r.Push(pmexec.Result{ExitCode: 1, Stderr: "Error: No such file or directory"}, nil)
		n := &nftables{base: base{ns: "app", cmd: cmd{r: r}}}
		rules, err := n.List(context.Background())
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("List(missing table) err = %v, want wrapped os.ErrNotExist", err)
		}
		if rules != nil {
			t.Fatalf("List(missing table) rules = %v, want nil", rules)
		}
	})
	t.Run("a real nft failure propagates", func(t *testing.T) {
		r := exectest.New(pmexec.Direct)
		r.Push(pmexec.Result{ExitCode: 1, Stderr: "Error: Operation not permitted"}, nil)
		n := &nftables{base: base{ns: "app", cmd: cmd{r: r}}}
		if _, err := n.List(context.Background()); err == nil {
			t.Fatal("a real nft failure must propagate, not read as 'no managed rules'")
		}
	})
}

func TestUfwList_EscalationFailurePropagates(t *testing.T) {
	r := exectest.New(pmexec.Direct)
	r.Push(pmexec.Result{}, pmexec.ErrEscalationDenied)
	u := &ufw{base: base{ns: "app", cmd: cmd{r: r}}}
	if _, err := u.List(context.Background()); !errors.Is(err, pmexec.ErrEscalationDenied) {
		t.Fatalf("ufw List err = %v, want ErrEscalationDenied propagated (not silent 'no rules')", err)
	}
}
