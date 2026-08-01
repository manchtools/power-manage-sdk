package sdk_test

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	_ "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1" // registers the contract descriptors
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

// removedLocalAuth is the second approved deletion delta: local human
// authentication. Target design 5.2 — human identity is OIDC plus SCIM only;
// there are no local accounts, passwords, TOTP secrets, or a local MFA
// implementation, because MFA belongs to the identity provider. These nine are
// the entire local-password/TOTP RPC surface.
//
// Everything else on the session path stays: RefreshToken, Logout,
// GetCurrentUser, ListAuthMethods, and the SSO*/SCIM* families are the
// OIDC-plus-SCIM flow itself, not local auth.
var removedLocalAuth = map[string][]string{
	"ControlService": {
		"AdminDisableUserTOTP",
		"DisableTOTP",
		"GetTOTPStatus",
		"Login",
		"RegenerateBackupCodes",
		"SetupTOTP",
		"UpdateUserPassword",
		"VerifyLoginTOTP",
		"VerifyTOTP",
	},
}

// removedAgentUnary is the target-design transport consolidation. AgentService
// exposes one long-lived bidirectional stream; synchronization and token
// validation are correlated frames on that stream, not parallel unary paths.
var removedAgentUnary = map[string][]string{
	"AgentService": {"SyncActions", "ValidateLuksToken"},
}

// removalDeltas are the approved deltas, subtracted cumulatively from the one
// golden predecessor. Keyed by name so a failure reports WHICH delta owns the
// offending RPC instead of just "not expected".
//
// New removals are added as a new delta rather than by growing an existing one
// or by re-capturing the golden: the golden is a committed reviewed artifact
// and the deltas are the reviewable record of what left the contract and why.
var removalDeltas = map[string]map[string][]string{
	"spec-41-gateway-removal": removedBySpec41,
	"local-auth-removal":      removedLocalAuth,
	"single-agent-stream":     removedAgentUnary,
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

// contractPackage is the protobuf namespace the contract ships under
// (target design §2). Every descriptor-level assertion in this file is scoped
// to it, so a stray descriptor from another module can never satisfy one.
const contractPackage = "powermanage.v1"

// liveSurface enumerates services and methods from the registered contract
// descriptors — the artifact that actually ships, not the .proto text.
func liveSurface(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if string(fd.Package()) != contractPackage {
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
		t.Fatalf("no %s services found in the descriptor registry — the enumeration is broken, "+
			"so a passing result would prove nothing", contractPackage)
	}
	return out
}

// removalOwner reports which delta deletes svc/name, if any.
func removalOwner(svc, name string) (string, bool) {
	for delta, byService := range removalDeltas {
		if contains(byService[svc], name) {
			return delta, true
		}
	}
	return "", false
}

// TestRPCSurface_MatchesGoldenMinusApprovedRemovals is the criterion-10 gate,
// extended to every approved removal delta rather than spec 41 alone.
func TestRPCSurface_MatchesGoldenMinusApprovedRemovals(t *testing.T) {
	golden := loadGolden(t)
	live := liveSurface(t)

	// Matches-zero: a delta map that decayed to empty (or a delta whose lists
	// all emptied) would turn "golden minus deltas" back into "golden", and the
	// removals would silently stop being verified as removals.
	if len(removalDeltas) == 0 {
		t.Fatal("no removal deltas declared — the subtraction below would be a no-op")
	}
	for delta, byService := range removalDeltas {
		n := 0
		for _, names := range byService {
			n += len(names)
		}
		if n == 0 {
			t.Fatalf("removal delta %q is empty — an empty delta removes nothing and asserts nothing", delta)
		}
	}

	// Deltas must be disjoint. A name listed twice is subtracted once but
	// counted twice by any per-delta arithmetic, and it means two reviews each
	// believe they own the same deletion.
	seen := map[string]string{}
	for delta, byService := range removalDeltas {
		for svc, names := range byService {
			for _, n := range names {
				key := svc + "/" + n
				if other, dup := seen[key]; dup {
					t.Errorf("%s is claimed by both removal deltas %q and %q", key, other, delta)
					continue
				}
				seen[key] = delta
			}
		}
	}

	// Every declared removal must exist in the predecessor. A typo here would
	// otherwise silently under-remove: the misspelled name is absent from the
	// golden, so subtracting it changes nothing.
	for delta, byService := range removalDeltas {
		for svc, names := range byService {
			have, ok := golden.Services[svc]
			if !ok {
				t.Fatalf("removal delta %q names service %q, absent from the golden predecessor", delta, svc)
			}
			for _, n := range names {
				if !contains(have, n) {
					t.Errorf("removal delta %q names %s/%s, which the predecessor never had — typo?", delta, svc, n)
				}
			}
		}
	}

	expected := map[string][]string{}
	for svc, names := range golden.Services {
		var keep []string
		for _, n := range names {
			if _, removed := removalOwner(svc, n); !removed {
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
				t.Errorf("MISSING: %s/%s is removed by no approved delta but is absent from the shipped descriptor", svc, n)
			}
		}
	}
	for svc, got := range live {
		for _, n := range got {
			if contains(expected[svc], n) {
				continue
			}
			if delta, removed := removalOwner(svc, n); removed {
				t.Errorf("UNEXPECTED: %s/%s is still shipped — removal delta %q deletes it", svc, n, delta)
				continue
			}
			t.Errorf("UNEXPECTED: %s/%s is shipped but the golden predecessor never had it "+
				"and no delta mentions it — the contract grew outside review", svc, n)
		}
	}

	// Independent arithmetic witness: count the removals straight off the
	// deltas instead of re-deriving them from `expected`, so a subtraction bug
	// in the loop above cannot agree with itself.
	removed := 0
	for _, byService := range removalDeltas {
		for _, names := range byService {
			removed += len(names)
		}
	}
	gotTotal := 0
	for _, v := range live {
		gotTotal += len(v)
	}
	if want := golden.Total - removed; gotTotal != want {
		t.Errorf("RPC count: shipped %d, expected %d (golden %d minus %d removals across %d deltas)",
			gotTotal, want, golden.Total, removed, len(removalDeltas))
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

// ---------------------------------------------------------------------------
// Contract shape guard: the message-level properties the target design fixes.
// Subject is the registered descriptor set, i.e. what actually ships.
// ---------------------------------------------------------------------------

// contractMessages returns every message (nested included) in the namespace
// that declares AgentService. The namespace is discovered, not hardcoded, so
// the sweeps below keep scanning the real descriptors while the namespace
// itself is being renamed; TestContract_Namespace judges the name.
func contractMessages(t *testing.T) map[protoreflect.Name]protoreflect.MessageDescriptor {
	t.Helper()
	var pkg protoreflect.FullName
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if fd.Services().ByName("AgentService") == nil {
			return true
		}
		pkg = fd.Package()
		return false
	})
	if pkg == "" {
		t.Fatal("no registered file declares AgentService — the contract descriptors are not linked in")
	}
	out := map[protoreflect.Name]protoreflect.MessageDescriptor{}
	var walk func(protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			out[mds.Get(i).Name()] = mds.Get(i)
			walk(mds.Get(i).Messages())
		}
	}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if fd.Package() == pkg {
			walk(fd.Messages())
		}
		return true
	})
	if len(out) == 0 {
		t.Fatalf("zero messages discovered in %s — the walk is broken", pkg)
	}
	return out
}

// Design §2: the contract lives under powermanage.v1. Both directions, so a
// rename that copied instead of moved (stale descriptors still registering at
// init) fails here.
func TestContract_Namespace(t *testing.T) {
	var shipped, legacy []string
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		switch string(fd.Package()) {
		case contractPackage:
			shipped = append(shipped, fd.Path())
		case "pm.v1":
			legacy = append(legacy, fd.Path())
		}
		return true
	})
	if len(shipped) == 0 {
		t.Errorf("no descriptors registered under %s — the contract namespace has not moved", contractPackage)
	}
	if len(legacy) != 0 {
		sort.Strings(legacy)
		t.Errorf("stale pm.v1 descriptors still registered: %s", strings.Join(legacy, ", "))
	}
}

// Design §7.1–7.2 (manifest dispatch, stable delivery id, durable receipt,
// per-action and per-manifest results) and §8 (sealed secrets, enrollment key
// exchange), asserted by exact name and exact type.
func TestContract_TargetShape(t *testing.T) {
	msgs := contractMessages(t)

	for _, name := range []protoreflect.Name{
		"Manifest", "ManifestProvenance", "ManifestOccurrence", "ManifestDelivery",
		"DeliveryReceipt", "ManifestResult", "SealedValue",
	} {
		if _, ok := msgs[name]; !ok {
			t.Errorf("message %s is absent from the shipped contract", name)
		}
	}
	for _, name := range []protoreflect.Name{"ActionDispatch", "SignedActionEnvelope"} {
		if _, ok := msgs[name]; ok {
			t.Errorf("message %s still ships — the signed-envelope dispatch path must be absent", name)
		}
	}
	// One dispatch model: the pull path carries the same durable unit as the
	// stream. The old standalone/group scheduler shape must be gone, not
	// coexisting.
	if _, ok := msgs["ActionGroup"]; ok {
		t.Error("message ActionGroup still ships — the pull path must deliver ManifestDeliveries, not schedule groups")
	}

	for _, f := range []struct {
		msg, field string
		kind       protoreflect.Kind
		msgType    protoreflect.Name // required when kind is MessageKind
		list       bool
		why        string
	}{
		{"Manifest", "manifest_id", protoreflect.StringKind, "", false, "the manifest has no identity"},
		{"Manifest", "provenance", protoreflect.MessageKind, "ManifestProvenance", false, "no bounded authoring provenance path"},
		{"Manifest", "occurrences", protoreflect.MessageKind, "ManifestOccurrence", true, "no ordered occurrence list"},
		{"ManifestOccurrence", "occurrence_id", protoreflect.StringKind, "", false, "authored positions are indistinguishable"},
		{"ManifestOccurrence", "action", protoreflect.MessageKind, "Action", false, "the occurrence carries no action"},
		{"ManifestOccurrence", "on_failure", protoreflect.EnumKind, "", false, "no per-occurrence failure policy"},
		{"ActionSet", "on_failure", protoreflect.EnumKind, "", false, "the set cannot retain its authored failure policy"},
		{"CreateActionSetRequest", "on_failure", protoreflect.EnumKind, "", false, "a set cannot be authored with STOP"},
		{"UpdateActionSetScheduleRequest", "on_failure", protoreflect.EnumKind, "", false, "the set execution policy cannot be changed"},
		{"ManifestDelivery", "delivery_id", protoreflect.StringKind, "", false, "delivery has no identity stable across transport retries"},
		{"ManifestDelivery", "manifest", protoreflect.MessageKind, "Manifest", false, "the delivery carries no manifest"},
		{"DeliveryReceipt", "delivery_id", protoreflect.StringKind, "", false, "the receipt names no delivery, so control cannot acknowledge one"},
		{"ActionResult", "delivery_id", protoreflect.StringKind, "", false, "per-action result ingestion cannot be idempotent"},
		{"ActionResult", "occurrence_id", protoreflect.StringKind, "", false, "per-action result ingestion cannot be idempotent"},
		{"ManifestResult", "delivery_id", protoreflect.StringKind, "", false, "the manifest result cannot be matched to its delivery"},
		{"ManifestResult", "manifest_id", protoreflect.StringKind, "", false, "the manifest result names no manifest"},
		{"SyncState", "deliveries", protoreflect.MessageKind, "ManifestDelivery", true, "stream synchronization is not on the one dispatch model"},
		{"ServerMessage", "manifest_delivery", protoreflect.MessageKind, "ManifestDelivery", false, "control cannot deliver a manifest"},
		{"AgentMessage", "delivery_receipt", protoreflect.MessageKind, "DeliveryReceipt", false, "the agent cannot confirm durable receipt"},
		{"AgentMessage", "manifest_result", protoreflect.MessageKind, "ManifestResult", false, "there is no result for the complete manifest"},
		{"SealedValue", "version", protoreflect.Uint32Kind, "", false, "the sealed envelope is unversioned"},
		{"SealedValue", "ciphertext", protoreflect.BytesKind, "", false, "the sealed envelope carries no ciphertext"},
		{"RegisterRequest", "agent_sealing_public_key", protoreflect.BytesKind, "", false, "control cannot seal a secret to this agent"},
		{"RegisterResponse", "control_sealing_public_key", protoreflect.BytesKind, "", false, "the agent cannot seal a secret to control"},
	} {
		md, ok := msgs[protoreflect.Name(f.msg)]
		if !ok {
			t.Errorf("%s.%s: message %s is absent", f.msg, f.field, f.msg)
			continue
		}
		fd := md.Fields().ByName(protoreflect.Name(f.field))
		if fd == nil {
			t.Errorf("%s has no %s — %s", f.msg, f.field, f.why)
			continue
		}
		if fd.Kind() != f.kind {
			t.Errorf("%s.%s is %s, want %s", f.msg, f.field, fd.Kind(), f.kind)
			continue
		}
		if f.kind == protoreflect.MessageKind && fd.Message().Name() != f.msgType {
			t.Errorf("%s.%s carries %s, want %s", f.msg, f.field, fd.Message().Name(), f.msgType)
		}
		if fd.IsList() != f.list {
			t.Errorf("%s.%s repeated = %v, want %v", f.msg, f.field, fd.IsList(), f.list)
		}
	}

	// §7.2: a crash after a persisted STARTED reports INDETERMINATE instead of
	// silently re-running. The enum is reached through the field that uses it.
	if status := msgs["ActionResult"].Fields().ByName("status"); status == nil || status.Enum() == nil {
		t.Error("ActionResult has no enum-typed status field")
	} else if status.Enum().Values().ByName("EXECUTION_STATUS_INDETERMINATE") == nil {
		t.Errorf("%s has no EXECUTION_STATUS_INDETERMINATE — a crash after STARTED has no honest terminal status",
			status.Enum().FullName())
	}
}

// Design §3 requires exactly one agent-control transport. This exact-set check
// prevents a future convenience RPC from silently reintroducing a second path.
func TestContract_AgentServiceIsOneStream(t *testing.T) {
	live := liveSurface(t)
	methods, ok := live["AgentService"]
	if !ok {
		t.Fatal("AgentService is absent")
	}
	if len(methods) != 1 || methods[0] != "Stream" {
		t.Fatalf("AgentService methods = %v, want exactly [Stream]", methods)
	}
}

// Design §8: every field classified secret ships sealed, and no application
// frame carries a signature or the relay-era device-binding guard. Both are
// registry sweeps rather than lists — a NEW secret or a NEW signature field
// fails without anyone remembering to extend anything.
func TestContract_SecretsAreSealedAndFramesAreUnsigned(t *testing.T) {
	msgs := contractMessages(t)
	banned := map[protoreflect.Name]string{
		"signature":          "a CA signature over an application frame",
		"signed_envelope":    "the signed-envelope indirection",
		"target_device_id":   "the relay-era device-binding guard (mTLS identifies the device)",
		"standalone_actions": "the abolished pull-path scheduler shape (deliveries carry manifests)",
		"grouped_actions":    "the abolished pull-path scheduler shape (deliveries carry manifests)",
	}

	classified, scanned := 0, 0
	for _, md := range msgs {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			scanned++
			if why, bad := banned[fd.Name()]; bad {
				t.Errorf("%s.%s still ships — %s has no place on a direct mTLS transport", md.Name(), fd.Name(), why)
			}
			opts, _ := fd.Options().(*descriptorpb.FieldOptions)
			if !opts.GetDebugRedact() {
				continue
			}
			classified++
			if fd.Kind() != protoreflect.MessageKind || fd.Message().Name() != "SealedValue" {
				t.Errorf("%s.%s is classified secret but ships as %s — it must be a SealedValue",
					md.Name(), fd.Name(), fd.Kind())
			}
		}
	}
	if scanned == 0 {
		t.Fatal("matches-zero: scanned zero fields — the signing sweep proved nothing")
	}
	if classified == 0 {
		t.Fatal("matches-zero: no field carries the secret classification (debug_redact) — " +
			"the marker convention was dropped, so the sealing sweep proved nothing")
	}
}
