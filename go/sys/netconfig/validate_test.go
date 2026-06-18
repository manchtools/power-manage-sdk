package netconfig

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateInterfaceConfig(t *testing.T) {
	base := func(mut func(*InterfaceConfig)) InterfaceConfig {
		c := InterfaceConfig{Name: "eth0", Mode: Static, Addresses: []string{"192.0.2.10/24"}}
		mut(&c)
		return c
	}
	cases := []struct {
		name    string
		cfg     InterfaceConfig
		wantErr bool
	}{
		{"valid static", base(func(c *InterfaceConfig) {}), false},
		{"valid dhcp", InterfaceConfig{Name: "eth0", Mode: DHCP}, false},
		{"valid full", base(func(c *InterfaceConfig) {
			c.Gateway = "192.0.2.1"
			c.DNS = []string{"1.1.1.1", "2001:db8::1"}
			c.MTU = 1500
			c.Routes = []Route{{Destination: "10.0.0.0/8", Gateway: "192.0.2.254", Metric: 100}, {Destination: "default", Gateway: "192.0.2.1"}}
		}), false},
		{"valid v6 static", InterfaceConfig{Name: "eth0", Mode: Static, Addresses: []string{"2001:db8::10/64"}}, false},
		{"bad ifname", base(func(c *InterfaceConfig) { c.Name = "-eth0" }), true},
		{"empty ifname", base(func(c *InterfaceConfig) { c.Name = "" }), true},
		{"mode unset", base(func(c *InterfaceConfig) { c.Mode = 0 }), true},
		{"static no addresses", InterfaceConfig{Name: "eth0", Mode: Static}, true},
		{"bad cidr", base(func(c *InterfaceConfig) { c.Addresses = []string{"192.0.2.10"} }), true}, // missing /prefix
		{"bad gateway", base(func(c *InterfaceConfig) { c.Gateway = "not-an-ip" }), true},
		{"bad dns", base(func(c *InterfaceConfig) { c.DNS = []string{"nope"} }), true},
		{"mtu too small", base(func(c *InterfaceConfig) { c.MTU = 10 }), true},
		{"mtu too large", base(func(c *InterfaceConfig) { c.MTU = 70000 }), true},
		{"route bad dest", base(func(c *InterfaceConfig) { c.Routes = []Route{{Destination: "garbage", Gateway: "192.0.2.1"}} }), true},
		{"route bad gateway", base(func(c *InterfaceConfig) { c.Routes = []Route{{Destination: "10.0.0.0/8", Gateway: "x"}} }), true},
		{"route negative metric", base(func(c *InterfaceConfig) {
			c.Routes = []Route{{Destination: "10.0.0.0/8", Gateway: "192.0.2.1", Metric: -1}}
		}), true},
		{"gateway family mismatch", base(func(c *InterfaceConfig) { c.Gateway = "2001:db8::1" }), true}, // v6 gw, v4-only address
		{"gateway family match v6", InterfaceConfig{Name: "eth0", Mode: Static, Addresses: []string{"2001:db8::10/64"}, Gateway: "2001:db8::1"}, false},
		{"gateway family match dual-stack", InterfaceConfig{Name: "eth0", Mode: Static, Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"}, Gateway: "2001:db8::1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInterfaceConfig(tc.cfg)
			if tc.wantErr && err == nil {
				t.Errorf("validate(%+v) = nil, want error", tc.cfg)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validate(%+v) = %v, want nil", tc.cfg, err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error must wrap ErrInvalidConfig, got %v", err)
			}
		})
	}
}

func TestPartitionHelpers(t *testing.T) {
	v4, v6 := partitionAddrsByFamily([]string{"192.0.2.10/24", "2001:db8::10/64", "garbage"})
	if strings.Join(v4, ",") != "192.0.2.10/24" || strings.Join(v6, ",") != "2001:db8::10/64" {
		t.Errorf("partitionAddrs = (%v,%v)", v4, v6)
	}
	v4, v6 = partitionIPsByFamily([]string{"1.1.1.1", "2001:db8::1", "nope"})
	if strings.Join(v4, ",") != "1.1.1.1" || strings.Join(v6, ",") != "2001:db8::1" {
		t.Errorf("partitionIPs = (%v,%v)", v4, v6)
	}
}
