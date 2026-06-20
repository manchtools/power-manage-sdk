package user

import (
	"context"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

type accountPersistenceAction int

const (
	accountCreateSystemNoLogin accountPersistenceAction = iota
	accountCreateRelativeHome
	accountCreateRootHomeWithChown
	accountCreateTmpShell
	accountModifyTmpHome
)

type accountPersistenceStep struct {
	name       string
	action     accountPersistenceAction
	wantReject bool
}

// TestAccountPersistenceSecurityMachine models account mutation as a tiny state
// machine around the agent's highest-risk persistence transitions. A permitted
// system account may be created with nologin, but attacker-controlled input must
// not reach useradd/usermod/chown when it would create relative homes, recursive
// ownership of system directories, or executable shells from writable locations.
func TestAccountPersistenceSecurityMachine(t *testing.T) {
	steps := []accountPersistenceStep{
		{name: "system nologin account is accepted", action: accountCreateSystemNoLogin},
		{name: "relative home is rejected before useradd", action: accountCreateRelativeHome, wantReject: true},
		{name: "root home ownership fixup is rejected before chown", action: accountCreateRootHomeWithChown, wantReject: true},
		{name: "tmp shell persistence is rejected before useradd", action: accountCreateTmpShell, wantReject: true},
		{name: "tmp home persistence is rejected before usermod", action: accountModifyTmpHome, wantReject: true},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			f := exectest.New(exec.Direct)
			ffs := newFakeFS().install(t)
			m := mgr(t, f)

			err := runAccountPersistenceStep(m, step.action)
			if step.wantReject {
				if err == nil {
					t.Errorf("%s reached an accepted state; want validation rejection", step.name)
				}
				if calls := f.Calls(); len(calls) != 0 {
					t.Errorf("%s reached command execution before rejection: %+v", step.name, calls)
				}
				if ffs.chown.called {
					t.Errorf("%s reached recursive ownership change: path=%q owner=%q group=%q", step.name, ffs.chown.path, ffs.chown.owner, ffs.chown.group)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s unexpected error: %v", step.name, err)
			}
		})
	}
}

func runAccountPersistenceStep(m Manager, action accountPersistenceAction) error {
	switch action {
	case accountCreateSystemNoLogin:
		return m.Create(context.Background(), "svc", CreateOptions{System: true})
	case accountCreateRelativeHome:
		return m.Create(context.Background(), "deploy", CreateOptions{HomeDir: "home/deploy"})
	case accountCreateRootHomeWithChown:
		return m.Create(context.Background(), "deploy", CreateOptions{HomeDir: "/", CreateHome: true})
	case accountCreateTmpShell:
		return m.Create(context.Background(), "deploy", CreateOptions{Shell: "/tmp/pwnsh"})
	case accountModifyTmpHome:
		return m.Modify(context.Background(), "deploy", ModifyOptions{HomeDir: "/tmp/deploy"})
	default:
		return nil
	}
}
