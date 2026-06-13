package verify

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
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

// OSQueryCanonical returns the signing pre-image bytes for an OSQuery. It
// binds query_id, table, columns, where, limit and raw_sql — so a compromised
// gateway cannot swap the table, inject raw_sql, or retarget the query under a
// valid signature.
func OSQueryCanonical(q *pmv1.OSQuery) ([]byte, error) {
	if q == nil {
		return nil, fmt.Errorf("verify: nil OSQuery")
	}
	c := proto.Clone(q).(*pmv1.OSQuery)
	c.Signature = nil
	return proto.MarshalOptions{Deterministic: true}.Marshal(c)
}

// LogQueryCanonical returns the signing pre-image bytes for a LogQuery. It
// binds query_id, unit, since, until, priority, grep, kernel, lines and
// source — so a compromised gateway cannot retarget the unit or widen the
// query under a valid signature.
func LogQueryCanonical(q *pmv1.LogQuery) ([]byte, error) {
	if q == nil {
		return nil, fmt.Errorf("verify: nil LogQuery")
	}
	c := proto.Clone(q).(*pmv1.LogQuery)
	c.Signature = nil
	return proto.MarshalOptions{Deterministic: true}.Marshal(c)
}

// RevokeLuksDeviceKeyCanonical returns the signing pre-image bytes for a
// RevokeLuksDeviceKey. It binds action_id, so a compromised gateway cannot
// forge or replay a slot-7 wipe onto any known action_id.
func RevokeLuksDeviceKeyCanonical(m *pmv1.RevokeLuksDeviceKey) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("verify: nil RevokeLuksDeviceKey")
	}
	c := proto.Clone(m).(*pmv1.RevokeLuksDeviceKey)
	c.Signature = nil
	return proto.MarshalOptions{Deterministic: true}.Marshal(c)
}

// RequestInventoryCanonical returns the signing pre-image bytes for a
// server-originated RequestInventory. It binds query_id so a compromised
// gateway cannot forge an inventory-collection command.
func RequestInventoryCanonical(m *pmv1.RequestInventory) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("verify: nil RequestInventory")
	}
	c := proto.Clone(m).(*pmv1.RequestInventory)
	c.Signature = nil
	return proto.MarshalOptions{Deterministic: true}.Marshal(c)
}
