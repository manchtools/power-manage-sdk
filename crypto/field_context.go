package crypto

import (
	"errors"
	"strconv"
)

// SealDirection is the authenticated transport direction of a sealed field.
type SealDirection string

const (
	DirectionAgentToControl SealDirection = "agent-to-control"
	DirectionControlToAgent SealDirection = "control-to-agent"
	fieldSealVersion                      = "power-manage-field-seal:v1"
)

// FieldSealContext constructs the shared AAD and HKDF domain used by control
// and agent for one secret-classified protobuf field. Bindings name the device
// followed by the relevant action, delivery, terminal session, or username.
// Length prefixes make the encoding unambiguous without restricting values.
// docref: begin sealed-field-context
func FieldSealContext(direction SealDirection, message, field string, bindings ...string) ([]byte, string, error) {
	if direction != DirectionAgentToControl && direction != DirectionControlToAgent {
		return nil, "", errors.New("crypto: invalid field-seal direction")
	}
	segments := make([]string, 0, 4+len(bindings))
	segments = append(segments, fieldSealVersion, string(direction), message, field)
	segments = append(segments, bindings...)
	for _, segment := range segments {
		if segment == "" {
			return nil, "", errors.New("crypto: field-seal context contains an empty segment")
		}
	}
	encoded := make([]byte, 0, 128)
	for _, segment := range segments {
		encoded = strconv.AppendInt(encoded, int64(len(segment)), 10)
		encoded = append(encoded, ':')
		encoded = append(encoded, segment...)
	}
	infoSegments := segments[:4]
	info := ""
	for _, segment := range infoSegments {
		info += strconv.Itoa(len(segment)) + ":" + segment
	}
	return encoded, info, nil
}

// docref: end sealed-field-context
