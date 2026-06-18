package antivirus_test

import (
	"context"
	"fmt"
	"log"

	"github.com/manchtools/power-manage/sdk/go/sys/antivirus"
	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// ExampleNew updates signatures then scans a path, printing any detections.
func ExampleNew() {
	r, err := exec.NewRunner(exec.Direct) // a full scan / update needs root
	if err != nil {
		log.Fatal(err)
	}
	m, err := antivirus.New(antivirus.ClamAV, r)
	if err != nil {
		log.Fatal(err)
	}
	if err := m.UpdateSignatures(context.Background()); err != nil {
		log.Print(err) // non-fatal: scan with current signatures anyway
	}
	res, err := m.Scan(context.Background(), "/home")
	if err != nil {
		log.Fatal(err)
	}
	for _, inf := range res.Infected {
		fmt.Printf("%s: %s\n", inf.File, inf.Signature)
	}
}
