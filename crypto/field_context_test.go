package crypto

import (
	"bytes"
	"testing"
)

func TestFieldSealContextBindsEveryTransportDimension(t *testing.T) {
	baseAAD, baseInfo, err := FieldSealContext(
		DirectionAgentToControl, "powermanage.v1.StoreLuksKeyRequest", "passphrase", "device", "action",
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		direction SealDirection
		message   string
		field     string
		bindings  []string
	}{
		{"direction", DirectionControlToAgent, "powermanage.v1.StoreLuksKeyRequest", "passphrase", []string{"device", "action"}},
		{"message", DirectionAgentToControl, "powermanage.v1.Other", "passphrase", []string{"device", "action"}},
		{"field", DirectionAgentToControl, "powermanage.v1.StoreLuksKeyRequest", "other", []string{"device", "action"}},
		{"device", DirectionAgentToControl, "powermanage.v1.StoreLuksKeyRequest", "passphrase", []string{"other-device", "action"}},
		{"action", DirectionAgentToControl, "powermanage.v1.StoreLuksKeyRequest", "passphrase", []string{"device", "other-action"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			aad, info, err := FieldSealContext(test.direction, test.message, test.field, test.bindings...)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(aad, baseAAD) {
				t.Fatal("changed context produced the same AAD")
			}
			if test.name == "direction" || test.name == "message" || test.name == "field" {
				if info == baseInfo {
					t.Fatal("changed field surface produced the same HKDF info")
				}
			} else if info != baseInfo {
				t.Fatal("per-value binding unexpectedly changed the field HKDF domain")
			}
		})
	}
}

func TestFieldSealContextIsUnambiguousAndRejectsMissingSegments(t *testing.T) {
	left, _, err := FieldSealContext(DirectionAgentToControl, "message", "field", "a:b", "c")
	if err != nil {
		t.Fatal(err)
	}
	right, _, err := FieldSealContext(DirectionAgentToControl, "message", "field", "a", "b:c")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(left, right) {
		t.Fatal("length-prefixed contexts collided")
	}
	if _, _, err := FieldSealContext("sideways", "message", "field", "device"); err == nil {
		t.Fatal("invalid direction accepted")
	}
	if _, _, err := FieldSealContext(DirectionAgentToControl, "message", "", "device"); err == nil {
		t.Fatal("empty field accepted")
	}
}
