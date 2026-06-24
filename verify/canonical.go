package verify

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// Canonical encoders for the non-action signing surfaces (osquery, log query,
// LUKS revoke, inventory). Each produces the deterministic protobuf wire bytes
// of its message WITH the signature field cleared — the exact bytes the
// control server signs (SignDomain) and the agent verifies (VerifyDomain).
//
// Clearing the signature before marshalling is what makes "sign the message
// itself" work: the signature can't cover itself, so both sides derive the
// pre-image from the same field set (everything except `signature`). This
// follows the same byte-for-byte philosophy as MarshalEnvelope for actions,
// and it auto-binds every field the message carries — including any field
// added later — without a hand-maintained field list that could drift from
// what the agent actually executes.
//
// Determinism: server (signs) and agent (verify) are both Go on the same SDK
// version and both use proto.MarshalOptions{Deterministic:true}, so the bytes
// agree. The gateway relays the proto message verbatim; it never re-derives or
// originates a signature.

// domainCanonical is the shared body behind every *Canonical encoder: it
// guards against a nil message, deterministically clones it, clears the
// `signature` field via protoreflect (so the signature can never cover
// itself), and returns the deterministic wire bytes. Clearing by field name
// keeps the four call sites identical and auto-binds every other field —
// including any added later — without a hand-maintained list. typeName names
// the message in the nil-guard error so each wrapper keeps its exact message.
func domainCanonical[T proto.Message](m T, typeName string) ([]byte, error) {
	// A typed-nil pointer reflects to an invalid message; treat it (and a nil
	// interface) as "no message" so each wrapper keeps its nil-guard contract.
	if !m.ProtoReflect().IsValid() {
		return nil, fmt.Errorf("verify: nil %s", typeName)
	}
	c := proto.Clone(m)
	r := c.ProtoReflect()
	if fd := r.Descriptor().Fields().ByName("signature"); fd != nil {
		r.Clear(fd)
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(c)
}

// OSQueryCanonical returns the signing pre-image bytes for an OSQuery. It
// binds query_id, table, columns, where, limit and raw_sql — so a compromised
// gateway cannot swap the table, inject raw_sql, or retarget the query under a
// valid signature.
func OSQueryCanonical(q *pmv1.OSQuery) ([]byte, error) {
	return domainCanonical(q, "OSQuery")
}

// LogQueryCanonical returns the signing pre-image bytes for a LogQuery. It
// binds query_id, unit, since, until, priority, grep, kernel, lines and
// source — so a compromised gateway cannot retarget the unit or widen the
// query under a valid signature.
func LogQueryCanonical(q *pmv1.LogQuery) ([]byte, error) {
	return domainCanonical(q, "LogQuery")
}

// RevokeLuksDeviceKeyCanonical returns the signing pre-image bytes for a
// RevokeLuksDeviceKey. It binds action_id, so a compromised gateway cannot
// forge or replay a slot-7 wipe onto any known action_id.
func RevokeLuksDeviceKeyCanonical(m *pmv1.RevokeLuksDeviceKey) ([]byte, error) {
	return domainCanonical(m, "RevokeLuksDeviceKey")
}

// RequestInventoryCanonical returns the signing pre-image bytes for a
// server-originated RequestInventory. It binds query_id so a compromised
// gateway cannot forge an inventory-collection command.
func RequestInventoryCanonical(m *pmv1.RequestInventory) ([]byte, error) {
	return domainCanonical(m, "RequestInventory")
}

// LpsPublicKeyCanonical returns the signing pre-image bytes for the control
// server's LPS sealing key (spec 18). It binds the public key bytes — so a
// compromised gateway cannot swap in its own key and read sealed passwords —
// while clearing the signature field the same way as every other surface.
func LpsPublicKeyCanonical(m *pmv1.LpsPublicKey) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("verify: nil LpsPublicKey")
	}
	c := proto.Clone(m).(*pmv1.LpsPublicKey)
	c.Signature = nil
	return proto.MarshalOptions{Deterministic: true}.Marshal(c)
}
