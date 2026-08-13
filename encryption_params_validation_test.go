package sdk_test

import (
	"strings"
	"testing"

	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	pmvalidate "github.com/manchtools/power-manage-sdk/validate"
)

// device_bound_key_type decides what goes into LUKS slot 7. Its validator tag
// was a bare `omitempty`, which constrains nothing on an enum: any int32 rode
// through the boundary, and the agent's switch over the value falls through to
// its default — "no device-bound key". So an operator (or a caller fuzzing the
// HTTPS write boundary) could ask for TPM enrollment with an out-of-range value
// and get a volume with NO device-bound key, silently, while the stored action
// still read as configured. An enum the boundary does not range-check is an
// enum the sink has to guess about.
//
// Both shapes carry the field: EncryptionParams is what the agent receives, and
// EncryptionAuthoringParams is the operator-facing write boundary that feeds it.
// Validating only the agent-facing shape would leave the front door open.

// definedDeviceBoundKeyTypes discovers the enum's legal values from the
// generated descriptor rather than hardcoding them, so adding a variant to the
// contract cannot leave this test asserting a stale set.
func definedDeviceBoundKeyTypes(t *testing.T) []pm.EncryptionDeviceBoundKeyType {
	t.Helper()
	var defined []pm.EncryptionDeviceBoundKeyType
	for n := range pm.EncryptionDeviceBoundKeyType_name {
		defined = append(defined, pm.EncryptionDeviceBoundKeyType(n))
	}
	if len(defined) == 0 {
		t.Fatal("discovered zero defined EncryptionDeviceBoundKeyType values; the enumeration source moved")
	}
	return defined
}

// undefinedDeviceBoundKeyTypes returns values outside the enum, derived from the
// same descriptor so it cannot accidentally name a value that later becomes
// legal.
func undefinedDeviceBoundKeyTypes(t *testing.T) []pm.EncryptionDeviceBoundKeyType {
	t.Helper()
	var out []pm.EncryptionDeviceBoundKeyType
	for _, n := range []int32{99, 3, -1, 2147483647} {
		if _, ok := pm.EncryptionDeviceBoundKeyType_name[n]; !ok {
			out = append(out, pm.EncryptionDeviceBoundKeyType(n))
		}
	}
	if len(out) == 0 {
		t.Fatal("every candidate out-of-range value is now a defined enum member; pick new ones")
	}
	return out
}

// mentionsDeviceBoundKeyType reports whether the validator's detail string
// blames the field under test. Asserting on the FIELD rather than on overall
// validity keeps the test independent of the other members' fixtures.
func mentionsDeviceBoundKeyType(detail string) bool {
	return strings.Contains(detail, "device_bound_key_type")
}

func TestEncryptionParams_RejectsUndefinedDeviceBoundKeyType(t *testing.T) {
	t.Parallel()
	v := pmvalidate.NewValidator()

	// A fully valid surrounding fixture, so the only thing under test is the enum.
	base := func(kt pm.EncryptionDeviceBoundKeyType) *pm.EncryptionParams {
		return &pm.EncryptionParams{
			PresharedKey:            &pm.SealedValue{Version: 1, Ciphertext: make([]byte, 61)},
			RotationIntervalDays:    30,
			MinWords:                5,
			DeviceBoundKeyType:      kt,
			UserPassphraseMinLength: 16,
		}
	}

	for _, kt := range definedDeviceBoundKeyTypes(t) {
		detail, _ := pmvalidate.Struct(v, base(kt))
		if mentionsDeviceBoundKeyType(detail) {
			t.Errorf("defined value %d (%s) was rejected: %s", int32(kt), kt, detail)
		}
	}
	for _, kt := range undefinedDeviceBoundKeyTypes(t) {
		detail, ok := pmvalidate.Struct(v, base(kt))
		if ok {
			t.Errorf("EncryptionParams with device_bound_key_type = %d passed validation; an out-of-range enum must be refused at the boundary, not silently degraded to 'no device-bound key' by the agent's switch default", int32(kt))
			continue
		}
		if !mentionsDeviceBoundKeyType(detail) {
			t.Errorf("device_bound_key_type = %d was rejected, but for another field: %s", int32(kt), detail)
		}
	}
}

func TestEncryptionAuthoringParams_RejectsUndefinedDeviceBoundKeyType(t *testing.T) {
	t.Parallel()
	v := pmvalidate.NewValidator()

	base := func(kt pm.EncryptionDeviceBoundKeyType) *pm.EncryptionAuthoringParams {
		return &pm.EncryptionAuthoringParams{
			RotationIntervalDays:    30,
			MinWords:                5,
			DeviceBoundKeyType:      kt,
			UserPassphraseMinLength: 16,
		}
	}

	for _, kt := range definedDeviceBoundKeyTypes(t) {
		detail, _ := pmvalidate.Struct(v, base(kt))
		if mentionsDeviceBoundKeyType(detail) {
			t.Errorf("defined value %d (%s) was rejected: %s", int32(kt), kt, detail)
		}
	}
	for _, kt := range undefinedDeviceBoundKeyTypes(t) {
		detail, ok := pmvalidate.Struct(v, base(kt))
		if ok {
			t.Errorf("EncryptionAuthoringParams with device_bound_key_type = %d passed validation; the operator-facing write boundary must range-check the enum", int32(kt))
			continue
		}
		if !mentionsDeviceBoundKeyType(detail) {
			t.Errorf("device_bound_key_type = %d was rejected, but for another field: %s", int32(kt), detail)
		}
	}
}
