package catrust_test

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/manchtools/power-manage-sdk/sys/catrust"
	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// ExampleNew installs an org CA into the system trust store, then lists the
// managed anchors.
func ExampleNew() {
	// Writing trust anchors requires root: exec.Direct assumes the process is
	// already root; from an unprivileged process use exec.NewRunner(exec.Sudo)
	// (or exec.Doas) so the writes and update-ca-trust refresh are escalated.
	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		log.Fatal(err)
	}
	m, err := catrust.New(catrust.CaCertificates, r)
	if err != nil {
		log.Fatal(err)
	}
	pem, err := os.ReadFile("/path/to/acme-root.pem")
	if err != nil {
		log.Fatal(err)
	}
	if err := m.Install(context.Background(), "acme-corp-root", pem); err != nil {
		log.Fatal(err)
	}
	anchors, err := m.List(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range anchors {
		fmt.Printf("%s: %s\n", a.Name, a.Subject)
	}
}
