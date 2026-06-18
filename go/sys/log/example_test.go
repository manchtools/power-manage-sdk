package log_test

import (
	"context"
	"fmt"
	"log"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	syslog "github.com/manchtools/power-manage/sdk/go/sys/log"
)

// ExampleNew reads recent warnings from a unit's journal.
func ExampleNew() {
	r, err := exec.NewRunner(exec.Direct) // the system journal needs root
	if err != nil {
		log.Fatal(err)
	}
	s, err := syslog.New(syslog.Journald, r)
	if err != nil {
		log.Fatal(err)
	}
	lines, err := s.Query(context.Background(), syslog.Query{
		Unit:     "sshd.service",
		Priority: "warning",
		Lines:    200,
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, l := range lines {
		fmt.Println(l)
	}
}
