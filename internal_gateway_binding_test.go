package sdk

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// TestInternalServiceDeviceIDRequestsCarryGatewayID is the self-discovering
// charter for the gateway↔control device-origin binding (server#403 / WS2): the
// control server can only confine a gateway to its own devices if every
// InternalService request that names a `device_id` ALSO carries the calling
// gateway's `gateway_id` to cross-check against the device→gateway routing
// binding. This walks the live InternalService descriptor (not a hardcoded
// list), so a NEW device-origin RPC added without a gateway_id field fails here
// rather than silently shipping an unbindable credential-bearing request.
//
// Requests that authenticate by other means (e.g. ValidateTerminalToken, which
// carries session_id + token, no device_id) are correctly excluded by the
// device_id-presence rule — no special-casing.
func TestInternalServiceDeviceIDRequestsCarryGatewayID(t *testing.T) {
	svc := pmv1.File_pm_v1_internal_proto.Services().ByName("InternalService")
	if svc == nil {
		t.Fatal("InternalService descriptor must resolve")
	}

	methods := svc.Methods()
	if methods.Len() == 0 {
		t.Fatal("matches-zero guard: InternalService exposes no methods")
	}

	// foundDeviceID counts requests the walk actually reached that carry a
	// device_id — the matches-zero guard. It is deliberately SEPARATE from the
	// pass/fail of the gateway_id check: if every device_id request were missing
	// gateway_id (the exact regression this guards), a counter that only
	// incremented on success would hit zero and misreport "no device_id request
	// exists" instead of the real failures.
	foundDeviceID := 0
	for i := 0; i < methods.Len(); i++ {
		req := methods.Get(i).Input()
		if req.Fields().ByName("device_id") == nil {
			continue // not a device-id-keyed request; binds via another credential
		}
		foundDeviceID++
		gw := req.Fields().ByName("gateway_id")
		if gw == nil {
			t.Errorf("%s carries device_id but no gateway_id — every device-origin InternalService request must bind to the calling gateway (WS2)", req.FullName())
			continue
		}
		if gw.Kind() != protoreflect.StringKind {
			t.Errorf("%s.gateway_id must be a string, got %s", req.FullName(), gw.Kind())
		}
	}
	if foundDeviceID == 0 {
		t.Fatal("matches-zero guard: no InternalService request carries device_id — the parity check is dead and would pass vacuously")
	}
}
