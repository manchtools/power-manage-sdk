package sdk_test

import (
	"strings"
	"testing"

	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	pmvalidate "github.com/manchtools/power-manage-sdk/validate"
)

// EncryptionParams' two enum members decide what protects a LUKS volume, and
// both carried a bare `omitempty`, which constrains nothing on an enum: any
// int32 rode through the boundary and the agent's switch over the value fell
// through to its default. For device_bound_key_type that default means "no
// device-bound key", so a request for TPM enrollment carrying an out-of-range
// value produced a volume with no device-bound key, silently, while the stored
// action still read as configured. An enum the boundary does not range-check is
// an enum the sink has to guess about.
//
// Both message shapes carry both fields: EncryptionParams is what the agent
// receives, and EncryptionAuthoringParams is the operator-facing HTTPS write
// boundary that feeds it. Validating only the agent-facing shape would leave
// the front door open.

// definedEnumValues discovers an enum's legal values from its generated _name
// map rather than hardcoding them, so adding a variant to the contract cannot
// leave this test asserting a stale set.
func definedEnumValues[E ~int32](t *testing.T, names map[int32]string) []E {
	t.Helper()
	var defined []E
	for n := range names {
		defined = append(defined, E(n))
	}
	if len(defined) == 0 {
		t.Fatal("discovered zero defined enum values; the enumeration source moved")
	}
	return defined
}

// undefinedEnumValues returns values outside the enum, filtered against the same
// _name map so a candidate that later becomes a legal member cannot silently
// stay in the list and turn this into a test of the opposite claim.
func undefinedEnumValues[E ~int32](t *testing.T, names map[int32]string) []E {
	t.Helper()
	var out []E
	for _, n := range []int32{99, 3, -1, 2147483647} {
		if _, ok := names[n]; !ok {
			out = append(out, E(n))
		}
	}
	if len(out) == 0 {
		t.Fatal("every candidate out-of-range value is now a defined enum member; pick new ones")
	}
	return out
}

// mentionsField reports whether the validator's detail string blames the field
// under test. Used for the REJECTION cases, where the point is that the refusal
// is attributed to the enum and not to some other member. The acceptance cases
// deliberately do NOT use it — see TestDefinedEnumLoopsRequireAValidFixture.
func mentionsField(detail, field string) bool { return strings.Contains(detail, field) }

// TestDefinedEnumLoopsRequireAValidFixture pins the blind spot the acceptance
// loops used to have, so it cannot be reintroduced.
//
// Those loops originally asserted only "the detail does not mention my field".
// That predicate is silently satisfied whenever validation fails for an
// UNRELATED reason: the detail names the other member, never ours, so the loop
// reports success while proving nothing about the enum it exists to test.
//
// This reproduces exactly that state — a params value whose enum is a defined,
// legal value but whose rotation_interval_days is invalid — and pins both
// halves: validation genuinely fails, AND the detail genuinely does not name the
// enum. Those two facts together are what made the old predicate a false pass,
// which is why the loops now require ok instead.
func TestDefinedEnumLoopsRequireAValidFixture(t *testing.T) {
	t.Parallel()
	v := pmvalidate.NewValidator()

	p := encryptionParamsFixture()
	p.DeviceBoundKeyType = pm.EncryptionDeviceBoundKeyType_ENCRYPTION_DEVICE_BOUND_KEY_TYPE_TPM // legal
	p.RotationIntervalDays = 0                                                                  // invalid, and unrelated to the enum

	detail, ok := pmvalidate.Struct(v, p)
	if ok {
		t.Fatalf("premise broken: rotation_interval_days = 0 must fail validation, got a pass (%s)", detail)
	}
	if !mentionsField(detail, "rotation_interval_days") {
		t.Errorf("expected the unrelated member to be blamed, got: %s", detail)
	}
	// The old acceptance predicate was `!mentionsField(detail, field)`. Here that
	// is true while validation is failing — a false pass. Requiring ok is what
	// closes it.
	if mentionsField(detail, "device_bound_key_type") {
		t.Errorf("premise broken: a legal enum value must not be blamed, got: %s", detail)
	}
}

// encryptionParamsFixture is a fully valid EncryptionParams; each test mutates
// exactly one enum member so that member is the only thing under test.
func encryptionParamsFixture() *pm.EncryptionParams {
	return &pm.EncryptionParams{
		PresharedKey:            &pm.SealedValue{Version: 1, Ciphertext: make([]byte, 61)},
		RotationIntervalDays:    30,
		MinWords:                5,
		UserPassphraseMinLength: 16,
	}
}

// encryptionAuthoringParamsFixture is the same for the write-boundary shape,
// whose preshared_key is optional on update.
func encryptionAuthoringParamsFixture() *pm.EncryptionAuthoringParams {
	return &pm.EncryptionAuthoringParams{
		RotationIntervalDays:    30,
		MinWords:                5,
		UserPassphraseMinLength: 16,
	}
}

func TestEncryptionParams_RejectsUndefinedDeviceBoundKeyType(t *testing.T) {
	t.Parallel()
	v := pmvalidate.NewValidator()
	const field = "device_bound_key_type"

	for _, kt := range definedEnumValues[pm.EncryptionDeviceBoundKeyType](t, pm.EncryptionDeviceBoundKeyType_name) {
		p := encryptionParamsFixture()
		p.DeviceBoundKeyType = kt
		if detail, valid := pmvalidate.Struct(v, p); !valid {
			t.Errorf("defined %s = %d (%s) must validate, got: %s", field, int32(kt), kt, detail)
		}
	}
	for _, kt := range undefinedEnumValues[pm.EncryptionDeviceBoundKeyType](t, pm.EncryptionDeviceBoundKeyType_name) {
		p := encryptionParamsFixture()
		p.DeviceBoundKeyType = kt
		detail, ok := pmvalidate.Struct(v, p)
		if ok {
			t.Errorf("EncryptionParams with %s = %d passed validation; an out-of-range enum must be refused at the boundary, not silently degraded to 'no device-bound key' by the agent's switch default", field, int32(kt))
			continue
		}
		if !mentionsField(detail, field) {
			t.Errorf("%s = %d was rejected, but for another field: %s", field, int32(kt), detail)
		}
	}
}

func TestEncryptionAuthoringParams_RejectsUndefinedDeviceBoundKeyType(t *testing.T) {
	t.Parallel()
	v := pmvalidate.NewValidator()
	const field = "device_bound_key_type"

	for _, kt := range definedEnumValues[pm.EncryptionDeviceBoundKeyType](t, pm.EncryptionDeviceBoundKeyType_name) {
		p := encryptionAuthoringParamsFixture()
		p.DeviceBoundKeyType = kt
		if detail, valid := pmvalidate.Struct(v, p); !valid {
			t.Errorf("defined %s = %d (%s) must validate, got: %s", field, int32(kt), kt, detail)
		}
	}
	for _, kt := range undefinedEnumValues[pm.EncryptionDeviceBoundKeyType](t, pm.EncryptionDeviceBoundKeyType_name) {
		p := encryptionAuthoringParamsFixture()
		p.DeviceBoundKeyType = kt
		detail, ok := pmvalidate.Struct(v, p)
		if ok {
			t.Errorf("EncryptionAuthoringParams with %s = %d passed validation; the operator-facing write boundary must range-check the enum", field, int32(kt))
			continue
		}
		if !mentionsField(detail, field) {
			t.Errorf("%s = %d was rejected, but for another field: %s", field, int32(kt), detail)
		}
	}
}

// user_passphrase_complexity is the same defect class in the same two messages:
// a bare `omitempty` on an enum. It selects the alphabet the agent draws a
// user-defined passphrase from, so an unvalidated value reaching the agent's
// switch falls through to its default alphabet — a weaker passphrase than the
// operator asked for, with nothing at the boundary saying so.
//
// The field stays OPTIONAL: it only applies when device_bound_key_type is
// USER_PASSPHRASE, so UNSPECIFIED (0) remains legal and the range check is
// added alongside omitempty rather than replacing it with a required rule.
func TestEncryptionParams_RejectsUndefinedUserPassphraseComplexity(t *testing.T) {
	t.Parallel()
	v := pmvalidate.NewValidator()
	const field = "user_passphrase_complexity"

	for _, c := range definedEnumValues[pm.LpsPasswordComplexity](t, pm.LpsPasswordComplexity_name) {
		p := encryptionParamsFixture()
		p.UserPassphraseComplexity = c
		if detail, valid := pmvalidate.Struct(v, p); !valid {
			t.Errorf("defined %s = %d (%s) must validate, got: %s", field, int32(c), c, detail)
		}
	}
	for _, c := range undefinedEnumValues[pm.LpsPasswordComplexity](t, pm.LpsPasswordComplexity_name) {
		p := encryptionParamsFixture()
		p.UserPassphraseComplexity = c
		detail, ok := pmvalidate.Struct(v, p)
		if ok {
			t.Errorf("EncryptionParams with %s = %d passed validation; an out-of-range enum must be refused at the boundary rather than resolving to the agent's default alphabet", field, int32(c))
			continue
		}
		if !mentionsField(detail, field) {
			t.Errorf("%s = %d was rejected, but for another field: %s", field, int32(c), detail)
		}
	}
}

func TestEncryptionAuthoringParams_RejectsUndefinedUserPassphraseComplexity(t *testing.T) {
	t.Parallel()
	v := pmvalidate.NewValidator()
	const field = "user_passphrase_complexity"

	for _, c := range definedEnumValues[pm.LpsPasswordComplexity](t, pm.LpsPasswordComplexity_name) {
		p := encryptionAuthoringParamsFixture()
		p.UserPassphraseComplexity = c
		if detail, valid := pmvalidate.Struct(v, p); !valid {
			t.Errorf("defined %s = %d (%s) must validate, got: %s", field, int32(c), c, detail)
		}
	}
	for _, c := range undefinedEnumValues[pm.LpsPasswordComplexity](t, pm.LpsPasswordComplexity_name) {
		p := encryptionAuthoringParamsFixture()
		p.UserPassphraseComplexity = c
		detail, ok := pmvalidate.Struct(v, p)
		if ok {
			t.Errorf("EncryptionAuthoringParams with %s = %d passed validation; the operator-facing write boundary must range-check the enum", field, int32(c))
			continue
		}
		if !mentionsField(detail, field) {
			t.Errorf("%s = %d was rejected, but for another field: %s", field, int32(c), detail)
		}
	}
}
