package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	_ "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestEveryBoundableRequestFieldCarriesValidateTag is the hard CI gate (it
// replaces the advisory os.Exit(0) scanner in main.go): every *bound-able*
// field of every `*Request` message type must carry a non-empty
// `validate:"..."` struct tag, so a new request field cannot reach a handler
// unvalidated.
//
// "Bound-able" is decided BY GO KIND (self-discovering, no name allow-list):
//   - REQUIRED: string, []byte, repeated/map of scalars, and BUILTIN integers
//     — these carry meaningful proto3 constraints (max length, dive bounds,
//     min/max value, ulid/format).
//   - EXEMPT: proto3 scalar bool / enum (a named integer type) / float, nested
//     messages and *Timestamp (pointers), repeated/map of messages, and oneof
//     wrappers — proto3 gives these no presence and no length/format to bound,
//     so a tag would be a no-op. (A proto3 `optional` scalar generates a
//     pointer and is treated as a message here; add a tag if one is wanted.)
//
// The list of violations is printed so a failure is actionable.
func TestEveryBoundableRequestFieldCarriesValidateTag(t *testing.T) {
	var requestTypes int
	var missing []string

	protoregistry.GlobalTypes.RangeMessages(func(mt protoreflect.MessageType) bool {
		name := string(mt.Descriptor().Name())
		if !strings.HasSuffix(name, "Request") {
			return true
		}
		requestTypes++
		goType := reflect.TypeOf(mt.Zero().Interface()).Elem()
		for i := 0; i < goType.NumField(); i++ {
			f := goType.Field(i)
			if f.Tag.Get("protobuf") == "" {
				continue // internal state / oneof wrapper / sizeCache
			}
			if !tagRequiredForKind(f.Type) {
				continue
			}
			if strings.TrimSpace(f.Tag.Get("validate")) == "" {
				missing = append(missing, name+"."+f.Name+" ("+f.Type.String()+")")
			}
		}
		return true
	})

	// Matches-zero guard: a registry that surfaced no request types (a generated
	// import that silently dropped, or a refactor) would otherwise let this pass
	// vacuously.
	if requestTypes == 0 {
		t.Fatal("no *Request message types discovered — the generated pm package did not register; the gate would pass vacuously")
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d bound-able request field(s) are missing a validate: tag — add a `// @gotags: validate:\"...\"` marker in the .proto and regenerate:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// tagRequiredForKind reports whether a request field of this Go type must carry
// a validate tag. See the test doc for the rationale.
func tagRequiredForKind(ft reflect.Type) bool {
	switch ft.Kind() {
	case reflect.String:
		return true
	case reflect.Slice:
		if ft.Elem().Kind() == reflect.Uint8 {
			return true // bytes
		}
		return isScalarKind(ft.Elem().Kind()) // repeated scalar/string; repeated message exempt
	case reflect.Map:
		return isScalarKind(ft.Elem().Kind()) // map of scalar values; map of message exempt
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		// A builtin integer (PkgPath == "") is bound-able (min/max). A NAMED
		// integer type is a proto enum — no proto3 presence/format to bound.
		return ft.PkgPath() == ""
	default:
		// bool, float, ptr (message / *Timestamp / proto3-optional), interface
		// (oneof), struct.
		return false
	}
}

func isScalarKind(k reflect.Kind) bool {
	switch k {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}
