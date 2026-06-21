package fs

import (
	"context"
	"os"
	"testing"

	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

type fileMutationAction int

const (
	fileMutationWriteConfig fileMutationAction = iota
	fileMutationWriteSetUID
	fileMutationChmodSetUID
	fileMutationCopySetUID
	fileMutationRecursiveChownRoot
)

type fileMutationStep struct {
	name       string
	action     fileMutationAction
	wantReject bool
}

// TestFileMutationSecurityMachine models privileged file operations as an
// attacker-facing state machine. Ordinary managed-config writes may reach the
// Runner; transitions that create privileged executable bits or recursively
// change ownership of root/system trees must fail before any escalated command.
func TestFileMutationSecurityMachine(t *testing.T) {
	steps := []fileMutationStep{
		{name: "managed config write is accepted", action: fileMutationWriteConfig},
		{name: "write with setuid mode is rejected before shell", action: fileMutationWriteSetUID, wantReject: true},
		{name: "chmod setuid is rejected before chmod", action: fileMutationChmodSetUID, wantReject: true},
		{name: "copy with setuid mode is rejected before cp", action: fileMutationCopySetUID, wantReject: true},
		{name: "recursive chown of root is rejected before chown", action: fileMutationRecursiveChownRoot, wantReject: true},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			r := exectest.New(pmexec.Sudo)
			m := mustManager(t, r)
			err := runFileMutationStep(m, step.action)
			if step.wantReject {
				if err == nil {
					t.Errorf("%s reached accepted state; want validation rejection", step.name)
				}
				if calls := r.Calls(); len(calls) != 0 {
					t.Fatalf("%s reached escalated command execution: %+v", step.name, calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s unexpected error: %v", step.name, err)
			}
			if calls := r.Calls(); len(calls) == 0 {
				t.Fatalf("%s did not exercise the accepted mutation path", step.name)
			}
		})
	}
}

func runFileMutationStep(m Manager, action fileMutationAction) error {
	setuidMode := os.FileMode(0o755) | os.ModeSetuid
	switch action {
	case fileMutationWriteConfig:
		return m.WriteFile(context.Background(), "/etc/pm-example.conf", []byte("ok\n"), WriteOptions{Mode: 0o644, Owner: "root", Group: "root"})
	case fileMutationWriteSetUID:
		return m.WriteFile(context.Background(), "/etc/pm-helper", []byte("#!/bin/sh\n"), WriteOptions{Mode: setuidMode, Owner: "root", Group: "root"})
	case fileMutationChmodSetUID:
		return m.SetMode(context.Background(), "/etc/pm-helper", setuidMode)
	case fileMutationCopySetUID:
		return m.Copy(context.Background(), "/etc/pm-src", "/etc/pm-helper", WriteOptions{Mode: setuidMode})
	case fileMutationRecursiveChownRoot:
		return m.SetOwnershipRecursive(context.Background(), "/", "root", "root")
	default:
		return nil
	}
}
