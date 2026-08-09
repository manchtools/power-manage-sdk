package sdk_test

import (
	"testing"

	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	pmvalidate "github.com/manchtools/power-manage-sdk/validate"
)

// TestAgentUpdateArchRequiresSignedChecksumManifest pins the signed-only public contract.
func TestAgentUpdateArchRequiresSignedChecksumManifest(t *testing.T) {
	t.Parallel()
	descriptor := (&pm.AgentUpdateArch{}).ProtoReflect().Descriptor()
	if descriptor.Fields().ByName("expected_sha256") != nil || descriptor.Fields().ByNumber(3) != nil {
		t.Fatal("expected_sha256 remains in the public agent-update contract")
	}
	if descriptor.ReservedNames().Has("expected_sha256") || descriptor.ReservedRanges().Has(3) {
		t.Fatal("expected_sha256 remains as reserved pre-alpha contract history")
	}

	validator := pmvalidate.NewValidator()
	tests := []struct {
		name        string
		checksumURL string
		wantOK      bool
	}{
		{name: "missing", wantOK: false},
		{name: "non-HTTPS", checksumURL: "http://releases.example/SHA256SUMS", wantOK: false},
		{name: "HTTPS", checksumURL: "https://releases.example/SHA256SUMS", wantOK: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := pmvalidate.Struct(validator, &pm.AgentUpdateArch{
				BinaryUrl:   "https://releases.example/power-manage-agent-linux-amd64",
				ChecksumUrl: tc.checksumURL,
			})
			if ok != tc.wantOK {
				t.Fatalf("validation = %v, want %v", ok, tc.wantOK)
			}
		})
	}
}
