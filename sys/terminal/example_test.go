package terminal_test

import (
	"context"
	"io"
	"log"

	"github.com/manchtools/power-manage-sdk/sys/terminal"
)

// ExampleManager_Open shows the construct-a-handle flow: build a Manager, open a
// PTY session as a user, drive it, and clean up. The Manager takes no Runner — a
// PTY is a long-lived bidirectional stream, not a captured one-shot command.
func ExampleManager_Open() {
	m, err := terminal.New()
	if err != nil {
		log.Fatal(err)
	}

	// ctx governs allocation only; the session outlives it (terminate with Close).
	sess, err := m.Open(context.Background(), terminal.SessionConfig{
		User: "alice",
		Cols: 80,
		Rows: 24,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sess.Close()

	if _, err := io.WriteString(sess, "echo hello\nexit\n"); err != nil {
		log.Fatal(err)
	}
	if _, err := sess.Wait(); err != nil {
		log.Print(err)
	}
}
