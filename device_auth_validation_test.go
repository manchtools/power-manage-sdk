package sdk_test

import (
	"strings"
	"testing"

	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	pmvalidate "github.com/manchtools/power-manage-sdk/validate"
)

func TestEnrollRequest_RequiresValidCAPin(t *testing.T) {
	t.Parallel()
	v := pmvalidate.NewValidator()

	tests := []struct {
		name, pin string
		wantOK    bool
	}{
		{name: "missing", wantOK: false},
		{name: "short", pin: "abcd", wantOK: false},
		{name: "one character short", pin: strings.Repeat("a", 63), wantOK: false},
		{name: "one character long", pin: strings.Repeat("a", 65), wantOK: false},
		{name: "non-hex", pin: strings.Repeat("z", 64), wantOK: false},
		{name: "valid lowercase", pin: strings.Repeat("a", 64), wantOK: true},
		{name: "valid uppercase", pin: strings.Repeat("A", 64), wantOK: true},
		{name: "valid mixed", pin: strings.Repeat("0123abcdABCD", 5) + "0123", wantOK: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := pmvalidate.Struct(v, &pm.EnrollRequest{
				ServerUrl: "https://control.example.test", Token: "token", CaFingerprintPin: tc.pin,
			})
			if ok != tc.wantOK {
				t.Fatalf("pin validation = %v, want %v", ok, tc.wantOK)
			}
		})
	}
}

func TestCreateTokenResponse_RequiresCAPin(t *testing.T) {
	t.Parallel()
	v := pmvalidate.NewValidator()
	response := &pm.CreateTokenResponse{Token: &pm.RegistrationToken{}}
	if _, ok := pmvalidate.Struct(v, response); ok {
		t.Fatal("token creation without the enrollment CA pin passed validation")
	}
	response.CaFingerprintPin = strings.Repeat("a", 64)
	if detail, ok := pmvalidate.Struct(v, response); !ok {
		t.Fatalf("valid token creation response rejected: %s", detail)
	}
}
