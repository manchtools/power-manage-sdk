package sdk_test

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	_ "github.com/manchtools/power-manage-sdk/gen/go/pm/v1" // registers the pm.v1 descriptors
)

// Spec 41 (gateway removal), acceptance criterion 10.
//
// The surviving RPC set is compared against a golden list captured from the
// PREDECESSOR descriptor, checked in at testdata/rpc_golden_pre_spec41.json.
//
// Why a checked-in golden and not a regenerated one: deriving both the expected
// and the actual set from the post-change descriptor makes the comparison
// vacuous — an RPC dropped by accident disappears from both sides and the test
// passes. This is the exact defect the manifest checker was rewritten to remove,
// so it is not being reintroduced here. The golden file is a reviewed commit; it
// is never regenerated from the tree under test.
const goldenPath = "testdata/rpc_golden_pre_spec41.json"

// removedBySpec41 is the deletion set the spec enumerates: the gateway tier and
// the relay-only plumbing that exists because an untrusted hop sat between agent
// and control. Listed per service so a name cannot be attributed to the wrong one.
var removedBySpec41 = map[string][]string{
	"GatewayAuthService": {"EnrollGateway"},
	"GatewayService":     {"ListGatewayTerminalSessions", "TerminateGatewayTerminalSession"},
	"ControlService": {
		"ListGateways",
		"RevokeGatewayCertificate",
		"GetCertificateRevocationList",
	},
	"InternalService": {
		"ProxyGetLuksKey",
		"ProxyStoreLpsPasswords",
		"ProxyStoreLuksKey",
		"ProxySyncActions",
		"ProxyValidateLuksToken",
		"ProxyValidateTerminalToken",
		"RenewGatewayCertificate",
		"VerifyDevice",
	},
}

type goldenSurface struct {
	Total    int                 `json:"total"`
	Services map[string][]string `json:"services"`
}

func loadGolden(t *testing.T) goldenSurface {
	t.Helper()
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v (it must be a committed artifact, never regenerated)", err)
	}
	var g goldenSurface
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	// Matches-zero: a golden that decayed to empty would make every assertion
	// below trivially true.
	if g.Total < 100 || len(g.Services) < 4 {
		t.Fatalf("golden looks truncated (total=%d services=%d) — refusing to verify against it",
			g.Total, len(g.Services))
	}
	// Self-consistency: `total` is recorded independently of the per-service
	// lists, so it is a second witness. Editing a name out of a list without
	// touching the total — the shape of a golden co-edited to match a mistaken
	// implementation change — fails here.
	sum := 0
	for _, v := range g.Services {
		sum += len(v)
	}
	if sum != g.Total {
		t.Fatalf("golden is internally inconsistent: total=%d but its service lists hold %d — "+
			"it has been edited by hand or regenerated from the wrong tree", g.Total, sum)
	}
	return g
}

// liveSurface enumerates services and methods from the registered pm.v1
// descriptors — the artifact that actually ships, not the .proto text.
func liveSurface(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if fd.Package() != "pm.v1" {
			return true
		}
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			sd := svcs.Get(i)
			name := string(sd.Name())
			// Record the service key BEFORE walking methods. Recording it only
			// inside the method loop made a zero-method service invisible, so
			// `service GatewayService {}` would have satisfied both tests below
			// — the exact vacuous-pass this file exists to prevent.
			if _, ok := out[name]; !ok {
				out[name] = []string{}
			}
			ms := sd.Methods()
			for j := 0; j < ms.Len(); j++ {
				out[name] = append(out[name], string(ms.Get(j).Name()))
			}
		}
		return true
	})
	for k := range out {
		sort.Strings(out[k])
	}
	if len(out) == 0 {
		t.Fatal("no pm.v1 services found in the descriptor registry — the enumeration is broken, " +
			"so a passing result would prove nothing")
	}
	return out
}

// TestRPCSurface_MatchesGoldenMinusSpec41Removals is the criterion-10 gate.
func TestRPCSurface_MatchesGoldenMinusSpec41Removals(t *testing.T) {
	golden := loadGolden(t)
	live := liveSurface(t)

	// Every declared removal must exist in the predecessor. A typo here would
	// otherwise silently under-remove: the misspelled name is absent from the
	// golden, so subtracting it changes nothing.
	for svc, names := range removedBySpec41 {
		have, ok := golden.Services[svc]
		if !ok {
			t.Fatalf("removal list names service %q, absent from the golden predecessor", svc)
		}
		for _, n := range names {
			if !contains(have, n) {
				t.Errorf("removal list names %s/%s, which the predecessor never had — typo?", svc, n)
			}
		}
	}

	expected := map[string][]string{}
	for svc, names := range golden.Services {
		var keep []string
		for _, n := range names {
			if !contains(removedBySpec41[svc], n) {
				keep = append(keep, n)
			}
		}
		if len(keep) > 0 {
			sort.Strings(keep)
			expected[svc] = keep
		}
	}

	for svc, want := range expected {
		got := live[svc]
		for _, n := range want {
			if !contains(got, n) {
				t.Errorf("MISSING: %s/%s survives spec 41 but is absent from the shipped descriptor", svc, n)
			}
		}
	}
	for svc, got := range live {
		for _, n := range got {
			if !contains(expected[svc], n) {
				t.Errorf("UNEXPECTED: %s/%s is still shipped — spec 41 removes it", svc, n)
			}
		}
	}

	wantTotal := 0
	for _, v := range expected {
		wantTotal += len(v)
	}
	gotTotal := 0
	for _, v := range live {
		gotTotal += len(v)
	}
	if gotTotal != wantTotal {
		t.Errorf("RPC count: shipped %d, expected %d (golden %d minus %d removals)",
			gotTotal, wantTotal, golden.Total, golden.Total-wantTotal)
	}
}

// TestRPCSurface_GatewayServicesAreGone names the whole-service deletions
// separately: the enumeration above compares METHOD names, so a service
// stripped to zero methods raises nothing there — its (empty) method list
// matches an absent expectation vacuously. Every service whose entire method
// set spec 41 removes has to be named here or nothing checks it at all.
//
// InternalService was missing from this list, which is the failure the comment
// describes: internal.proto is deleted, and had it survived with its methods
// intact the enumeration would have caught it — but a partially-stripped one
// would have passed both.
func TestRPCSurface_GatewayServicesAreGone(t *testing.T) {
	live := liveSurface(t)
	for _, svc := range []string{"GatewayAuthService", "GatewayService", "InternalService"} {
		if methods, ok := live[svc]; ok {
			t.Errorf("service %s is still registered with %d method(s): %s",
				svc, len(methods), strings.Join(methods, ", "))
		}
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
