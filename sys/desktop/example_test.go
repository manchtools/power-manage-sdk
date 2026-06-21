package desktop_test

import (
	"context"
	"log"

	"github.com/manchtools/power-manage-sdk/sys/desktop"
	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// ExampleManager_ActiveSessions discovers the active graphical sessions and
// builds, for each, a Runner that executes AS that session's user via
// desktop.RunAsRunner — the way a user-scoped command (e.g. a per-user Flatpak
// install) is fanned out to every signed-in user.
func ExampleManager_ActiveSessions() {
	r, err := exec.NewRunner(exec.Direct) // the agent runs as root
	if err != nil {
		log.Fatal(err)
	}
	m, err := desktop.New(r)
	if err != nil {
		log.Fatal(err)
	}

	sessions, err := m.ActiveSessions(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range sessions {
		ru, err := desktop.RunAsRunner(r, s)
		if err != nil {
			log.Print(err)
			continue
		}
		_ = ru // e.g. pkg.New(pkg.Flatpak, ru, pkg.WithUserScope()).Install(ctx, …)
	}
}
