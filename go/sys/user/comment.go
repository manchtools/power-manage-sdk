package user

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidComment is returned when a GECOS / comment value contains a
// character that would corrupt the colon-delimited /etc/passwd record.
var ErrInvalidComment = errors.New("invalid comment")

// ValidateComment guards the GECOS / comment field before it reaches
// `useradd/usermod -c <comment>`. The value becomes a colon-delimited
// field in /etc/passwd, so a ':' would split the record into spurious
// fields and a newline would forge an entire record; NUL/CR are rejected
// for the same record-integrity reason. An empty comment is allowed
// ("no comment"). Commas are permitted because GECOS legitimately uses
// them to separate sub-fields (full name, room, phone).
func ValidateComment(comment string) error {
	if comment == "" {
		return nil
	}
	if i := strings.IndexAny(comment, ":\n\r\x00"); i >= 0 {
		return fmt.Errorf("%w: contains %q at offset %d (':' and control characters corrupt the passwd record)", ErrInvalidComment, comment[i], i)
	}
	return nil
}
