package netconfig_test

import (
	"context"
	"log"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/netconfig"
)

// ExampleNew shows the construct-a-handle flow: pick a backend (here
// systemd-networkd), build a Manager over a Runner, and apply a static IP
// config with a default route.
func ExampleNew() {
	r, err := exec.NewRunner(exec.Direct) // the agent runs as root
	if err != nil {
		log.Fatal(err)
	}
	m, err := netconfig.New(netconfig.SystemdNetworkd, r)
	if err != nil {
		log.Fatal(err)
	}
	if err := m.Apply(context.Background(), netconfig.InterfaceConfig{
		Name:      "eth0",
		Mode:      netconfig.Static,
		Addresses: []string{"192.0.2.10/24"},
		Gateway:   "192.0.2.1",
		DNS:       []string{"1.1.1.1"},
		MTU:       1500,
		Routes:    []netconfig.Route{{Destination: "10.0.0.0/8", Gateway: "192.0.2.254"}},
	}); err != nil {
		log.Fatal(err)
	}
}
