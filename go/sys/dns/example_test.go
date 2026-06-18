package dns_test

import (
	"context"
	"log"

	"github.com/manchtools/power-manage/sdk/go/sys/dns"
	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// ExampleNew shows the construct-a-handle flow: pick a backend (here
// systemd-resolved), build a Manager over a Runner, and apply a host-global
// resolver config.
func ExampleNew() {
	r, err := exec.NewRunner(exec.Direct) // the agent runs as root
	if err != nil {
		log.Fatal(err)
	}
	m, err := dns.New(dns.Resolved, r)
	if err != nil {
		log.Fatal(err)
	}
	if err := m.Apply(context.Background(), dns.Config{
		Nameservers:   []string{"1.1.1.1", "9.9.9.9"},
		SearchDomains: []string{"corp.example"},
	}); err != nil {
		log.Fatal(err)
	}
}
