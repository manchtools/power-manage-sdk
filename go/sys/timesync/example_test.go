package timesync_test

import (
	"context"
	"fmt"
	"log"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/timesync"
)

// ExampleNew reads the clock-sync status from chrony.
func ExampleNew() {
	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		log.Fatal(err)
	}
	m, err := timesync.New(timesync.Chrony, r)
	if err != nil {
		log.Fatal(err)
	}
	st, err := m.Status(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("synchronized=%v source=%s offset=%.6fs\n", st.Synchronized, st.Source, st.OffsetSeconds)
}
