package verify

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// MarshalEnvelope returns the deterministic protobuf wire bytes of a
// SignedActionEnvelope — the exact bytes the CA signs (ActionSigner.Sign),
// the gateway transports (ActionDispatch.envelope), and the agent verifies
// then unmarshals to execute. Always use this rather than a plain
// proto.Marshal so signer and verifier agree on byte layout; deterministic
// marshalling pins map/field ordering across Go versions as belt-and-braces
// (the load-bearing guarantee is that the SAME bytes are transported and
// executed, not re-marshalled).
func MarshalEnvelope(env *pmv1.SignedActionEnvelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("verify: nil SignedActionEnvelope")
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(env)
}
