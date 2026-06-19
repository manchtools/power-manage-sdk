package desktop_test

import (
	"context"
	"log"

	"github.com/manchtools/power-manage-sdk/sys/desktop"
	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// ExampleManager_ActiveSessions shows fanning a user-scoped command out to every
// active graphical session. The loginctl probe runs through the Runner (forced
// C locale); RunAsCommand builds a command that keeps the user's own locale.
func ExampleManager_ActiveSessions() {
	r, err := exec.NewRunner(exec.Direct) // the agent runs as root
	if err != nil {
		log.Fatal(err)
	}
	m, err := desktop.New(r)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	sessions, err := m.ActiveSessions(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range sessions {
		cmd, err := m.RunAsCommand(ctx, s, desktop.RunAsOptions{}, "/usr/bin/flatpak", "--user", "update", "-y")
		if err != nil {
			log.Print(err)
			continue
		}
		_ = cmd.Run() // run the per-user command (errors handled per the caller's policy)
	}
}
