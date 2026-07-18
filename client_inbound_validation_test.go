package sdk

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// recordingHandler implements StreamHandler plus every optional command
// interface (Inventory/LogQuery/Luks), counting how often each command
// callback is invoked. Used to prove that a malformed inbound command is
// dropped by validateInbound BEFORE it reaches the handler, and — as a
// guard against a vacuous pass — that a well-formed one still gets through.
type recordingHandler struct {
	osqueryCalls   int32
	inventoryCalls int32
	logQueryCalls  int32
	luksCalls      int32
}

func (h *recordingHandler) OnWelcome(context.Context, *pm.Welcome) error { return nil }
func (h *recordingHandler) OnAction(context.Context, []byte, []byte) (*pm.ActionResult, error) {
	return nil, nil
}
func (h *recordingHandler) OnQuery(context.Context, *pm.OSQuery) (*pm.OSQueryResult, error) {
	atomic.AddInt32(&h.osqueryCalls, 1)
	return nil, nil
}
func (h *recordingHandler) OnError(context.Context, *pm.Error) error { return nil }
func (h *recordingHandler) CollectInventory(context.Context) *pm.DeviceInventory {
	return nil
}
func (h *recordingHandler) OnRequestInventory(context.Context, *pm.RequestInventory) *pm.DeviceInventory {
	atomic.AddInt32(&h.inventoryCalls, 1)
	return nil
}
func (h *recordingHandler) OnLogQuery(context.Context, *pm.LogQuery) (*pm.LogQueryResult, error) {
	atomic.AddInt32(&h.logQueryCalls, 1)
	return nil, nil
}
func (h *recordingHandler) OnRevokeLuksDeviceKey(context.Context, *pm.RevokeLuksDeviceKey) (bool, string) {
	atomic.AddInt32(&h.luksCalls, 1)
	return false, ""
}

// validULID is a syntactically valid ULID; badULID fails the
// `validate:"required,ulid"` rule the command payloads carry on their
// query_id / action_id field — and, since PMSEC-001, on their
// target_device_id field too.
const (
	validULID = "01HQ0000000000000000000000"
	badULID   = "not-a-ulid"
)

// TestDispatch_RejectsInvalidInboundCommands pins the WS0 P0.3 fix: the
// RequestInventory, LogQuery and RevokeLuksDeviceKey dispatch branches must run
// validateInbound — exactly like Action/Query/Terminal* — so a compromised
// relay cannot push a malformed-but-non-nil command past the SDK boundary into
// a handler. The RevokeLuksDeviceKey case matters most: it drives the
// irreversible LUKS slot-7 wipe.
//
// Each subtest asserts BOTH directions: a non-ULID id NEVER reaches the handler
// (the rejection — the point of the test), and a valid ULID DOES (so the test
// can't pass vacuously because the handler interface went unsatisfied).
func TestDispatch_RejectsInvalidInboundCommands(t *testing.T) {
	// Each builder sets a VALID target_device_id (also `required,ulid` since
	// PMSEC-001) so `id` — the query_id / action_id — stays the only field
	// under test here. target_device_id gets its own rejection test below.
	mkInventory := func(id string) *pm.ServerMessage {
		return &pm.ServerMessage{Id: "m", Payload: &pm.ServerMessage_RequestInventory{
			RequestInventory: &pm.RequestInventory{QueryId: id, TargetDeviceId: validULID}}}
	}
	mkLogQuery := func(id string) *pm.ServerMessage {
		return &pm.ServerMessage{Id: "m", Payload: &pm.ServerMessage_LogQuery{
			LogQuery: &pm.LogQuery{QueryId: id, TargetDeviceId: validULID}}}
	}
	mkLuks := func(id string) *pm.ServerMessage {
		return &pm.ServerMessage{Id: "m", Payload: &pm.ServerMessage_RevokeLuksDeviceKey{
			RevokeLuksDeviceKey: &pm.RevokeLuksDeviceKey{ActionId: id, TargetDeviceId: validULID}}}
	}

	cases := []struct {
		name  string
		build func(id string) *pm.ServerMessage
		count func(*recordingHandler) int32
	}{
		{"RequestInventory", mkInventory, func(h *recordingHandler) int32 { return atomic.LoadInt32(&h.inventoryCalls) }},
		{"LogQuery", mkLogQuery, func(h *recordingHandler) int32 { return atomic.LoadInt32(&h.logQueryCalls) }},
		{"RevokeLuksDeviceKey", mkLuks, func(h *recordingHandler) int32 { return atomic.LoadInt32(&h.luksCalls) }},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"/invalid_id_never_reaches_handler", func(t *testing.T) {
			c := NewClient("https://gw.invalid", WithAuth(validULID, ""))
			h := &recordingHandler{}
			if err := c.dispatchServerMessage(context.Background(), tc.build(badULID), h); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			// RequestInventory and RevokeLuksDeviceKey run the handler on a
			// spawned goroutine; settle so an unguarded dispatch would have
			// invoked it before we assert zero.
			settle()
			if got := tc.count(h); got != 0 {
				t.Fatalf("%s: a non-ULID id reached the handler %d time(s); validateInbound must drop it at the boundary", tc.name, got)
			}
		})

		t.Run(tc.name+"/valid_id_reaches_handler", func(t *testing.T) {
			c := NewClient("https://gw.invalid", WithAuth(validULID, ""))
			h := &recordingHandler{}
			if err := c.dispatchServerMessage(context.Background(), tc.build(validULID), h); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			waitForCond(t, func() bool { return tc.count(h) == 1 })
		})
	}
}

// settle waits a short, fixed period for a dispatch-spawned goroutine to have
// run, so a "handler must NOT be called" assertion is not racing the spawn.
func settle() { time.Sleep(150 * time.Millisecond) }

// TestDispatch_RejectsMissingOrInvalidTargetDeviceId pins the PMSEC-001 hardening:
// all four non-action stream-RPC payloads (OSQuery, RequestInventory, LogQuery,
// RevokeLuksDeviceKey) now carry `validate:"required,ulid"` on target_device_id,
// so validateInbound drops a command that names no target device (or a malformed
// one) at the SDK boundary — before it reaches a privileged handler. A missing
// target is exactly the shape a target-stripped or pre-binding relay frame has;
// dropping it is defence-in-depth beneath the agent's own target==self check.
//
// Each surface asserts BOTH a missing and a non-ULID target are dropped, and — as
// a guard against a vacuous pass — that a valid target still reaches the handler.
func TestDispatch_RejectsMissingOrInvalidTargetDeviceId(t *testing.T) {
	// build(target) sets a VALID query/action id and the given target_device_id,
	// so target_device_id is the only field under test.
	mkOSQuery := func(target string) *pm.ServerMessage {
		return &pm.ServerMessage{Id: "m", Payload: &pm.ServerMessage_Query{
			Query: &pm.OSQuery{QueryId: validULID, Table: "processes", TargetDeviceId: target}}}
	}
	mkInventory := func(target string) *pm.ServerMessage {
		return &pm.ServerMessage{Id: "m", Payload: &pm.ServerMessage_RequestInventory{
			RequestInventory: &pm.RequestInventory{QueryId: validULID, TargetDeviceId: target}}}
	}
	mkLogQuery := func(target string) *pm.ServerMessage {
		return &pm.ServerMessage{Id: "m", Payload: &pm.ServerMessage_LogQuery{
			LogQuery: &pm.LogQuery{QueryId: validULID, TargetDeviceId: target}}}
	}
	mkLuks := func(target string) *pm.ServerMessage {
		return &pm.ServerMessage{Id: "m", Payload: &pm.ServerMessage_RevokeLuksDeviceKey{
			RevokeLuksDeviceKey: &pm.RevokeLuksDeviceKey{ActionId: validULID, TargetDeviceId: target}}}
	}

	cases := []struct {
		name  string
		build func(target string) *pm.ServerMessage
		count func(*recordingHandler) int32
	}{
		{"OSQuery", mkOSQuery, func(h *recordingHandler) int32 { return atomic.LoadInt32(&h.osqueryCalls) }},
		{"RequestInventory", mkInventory, func(h *recordingHandler) int32 { return atomic.LoadInt32(&h.inventoryCalls) }},
		{"LogQuery", mkLogQuery, func(h *recordingHandler) int32 { return atomic.LoadInt32(&h.logQueryCalls) }},
		{"RevokeLuksDeviceKey", mkLuks, func(h *recordingHandler) int32 { return atomic.LoadInt32(&h.luksCalls) }},
	}

	bad := []struct{ label, target string }{
		{"missing_target", ""},
		{"nonulid_target", badULID},
	}

	for _, tc := range cases {
		tc := tc
		for _, b := range bad {
			b := b
			t.Run(tc.name+"/"+b.label+"_never_reaches_handler", func(t *testing.T) {
				c := NewClient("https://gw.invalid", WithAuth(validULID, ""))
				h := &recordingHandler{}
				if err := c.dispatchServerMessage(context.Background(), tc.build(b.target), h); err != nil {
					t.Fatalf("dispatch: %v", err)
				}
				// The async surfaces run the handler on a spawned goroutine;
				// settle so an unguarded dispatch would have reached it.
				settle()
				if got := tc.count(h); got != 0 {
					t.Fatalf("%s: a command with a %s reached the handler %d time(s); validateInbound must drop it at the boundary (PMSEC-001)", tc.name, b.label, got)
				}
			})
		}
		t.Run(tc.name+"/valid_target_reaches_handler", func(t *testing.T) {
			c := NewClient("https://gw.invalid", WithAuth(validULID, ""))
			h := &recordingHandler{}
			if err := c.dispatchServerMessage(context.Background(), tc.build(validULID), h); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			waitForCond(t, func() bool { return tc.count(h) == 1 })
		})
	}
}

// TestDispatchValidatesEveryInboundCommand is the self-discovering regression
// guard for P0.3: it walks EVERY ServerMessage oneof arm whose payload carries
// `validate` gotags and asserts that dispatchServerMessage runs validateInbound
// for it — so a newly-added command RPC cannot silently skip validation again.
//
// Exemptions are by intrinsic KIND, not a name list:
//   - response arms whose case delivers to a pending caller (deliverPending) —
//     validated at the request site, not at dispatch; and
//   - connection-lifecycle arms (OnWelcome / OnError) — these carry no
//     operator-issued command parameters that drive privileged device work.
//
// The set is discovered from the proto descriptor + the dispatch AST, with a
// matches-zero guard and a guard that every discovered arm is actually handled
// by a dispatch case, so descriptor/registry drift can't pass the check
// vacuously.
func TestDispatchValidatesEveryInboundCommand(t *testing.T) {
	// 1. Discover, from the descriptor, the ServerMessage oneof arms whose Go
	//    payload type carries validate gotags.
	md := (&pm.ServerMessage{}).ProtoReflect().Descriptor()
	oneof := md.Oneofs().ByName("payload")
	if oneof == nil {
		t.Fatal("ServerMessage has no 'payload' oneof — descriptor drift")
	}
	validatable := map[string]bool{} // wrapper Go type name -> has validate gotags
	for i := 0; i < oneof.Fields().Len(); i++ {
		fd := oneof.Fields().Get(i)
		if fd.Message() == nil {
			continue // scalar oneof arm (none today)
		}
		gt := messageGoType(fd.Message().FullName())
		if gt == nil {
			t.Fatalf("cannot resolve Go type for %s (registry drift)", fd.Message().FullName())
		}
		if typeHasValidateTag(gt, map[reflect.Type]bool{}) {
			validatable["ServerMessage_"+goCamel(string(fd.Name()))] = true
		}
	}
	if len(validatable) == 0 {
		t.Fatal("matches-zero guard: discovered zero validatable ServerMessage oneof arms — descriptor/registry drift?")
	}

	// 2. Classify each dispatch case from the AST.
	cases := parseDispatchCases(t)

	commandArms := 0
	for wrapper := range validatable {
		info, handled := cases[wrapper]
		if !handled {
			t.Errorf("oneof arm %q carries validate gotags but has no dispatchServerMessage case — unhandled inbound (drift)", wrapper)
			continue
		}
		if info.deliversPending || info.lifecycle {
			continue // exempt by kind (response / lifecycle)
		}
		commandArms++
		if !info.validates {
			t.Errorf("dispatchServerMessage case %q drives a command handler but does NOT call validateInbound — inbound-validation gap (WS0 P0.3)", wrapper)
		}
	}
	if commandArms == 0 {
		t.Fatal("matches-zero guard: classified zero command arms requiring validateInbound — AST classifier drift?")
	}
}

// dispatchCaseInfo records what an AST dispatch case does, for kind-based
// classification.
type dispatchCaseInfo struct {
	validates       bool // calls c.validateInbound(...)
	deliversPending bool // calls c.deliverPending(...) — request-response arm
	lifecycle       bool // calls handler.OnWelcome / handler.OnError — lifecycle arm
}

// parseDispatchCases parses client.go, locates dispatchServerMessage's type
// switch, and returns per-arm (ServerMessage_X wrapper name) classification.
func parseDispatchCases(t *testing.T) map[string]dispatchCaseInfo {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "client.go", nil, 0)
	if err != nil {
		t.Fatalf("parse client.go: %v", err)
	}

	out := map[string]dispatchCaseInfo{}
	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "dispatchServerMessage" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("dispatchServerMessage not found in client.go — refactor without updating the parity guard?")
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		// Collect the ServerMessage_X wrapper names this case matches.
		var wrappers []string
		for _, expr := range cc.List {
			star, ok := expr.(*ast.StarExpr)
			if !ok {
				continue
			}
			sel, ok := star.X.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if strings.HasPrefix(sel.Sel.Name, "ServerMessage_") {
				wrappers = append(wrappers, sel.Sel.Name)
			}
		}
		if len(wrappers) == 0 {
			return true
		}
		// Scan the case body for the classifying calls.
		var info dispatchCaseInfo
		for _, stmt := range cc.Body {
			ast.Inspect(stmt, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "validateInbound":
					info.validates = true
				case "deliverPending":
					info.deliversPending = true
				case "OnWelcome", "OnError":
					info.lifecycle = true
				}
				return true
			})
		}
		for _, w := range wrappers {
			out[w] = info
		}
		return true
	})
	return out
}

// messageGoType resolves a proto message full name to its generated Go pointer
// type via the global type registry.
func messageGoType(name protoreflect.FullName) reflect.Type {
	mt, err := protoregistry.GlobalTypes.FindMessageByName(name)
	if err != nil {
		return nil
	}
	return reflect.TypeOf(mt.New().Interface())
}

// typeHasValidateTag reports whether t (or any nested message type reachable
// from it) declares a non-empty `validate` struct tag. seen guards against
// recursive proto types; pass a fresh map per top-level query.
func typeHasValidateTag(t reflect.Type, seen map[reflect.Type]bool) bool {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return false
	}
	seen[t] = true
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported (state, sizeCache, unknownFields)
		}
		if v, ok := f.Tag.Lookup("validate"); ok && v != "" {
			return true
		}
		ft := f.Type
		for ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		switch ft.Kind() {
		case reflect.Struct:
			if typeHasValidateTag(ft, seen) {
				return true
			}
		case reflect.Slice:
			et := ft.Elem()
			for et.Kind() == reflect.Ptr {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct && typeHasValidateTag(et, seen) {
				return true
			}
		}
	}
	return false
}

// goCamel converts a proto field name (snake_case) to the Go camel-case used in
// the generated oneof wrapper type name (matches protoc-gen-go for the
// digit-free field names of ServerMessage).
func goCamel(snake string) string {
	parts := strings.Split(snake, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}
