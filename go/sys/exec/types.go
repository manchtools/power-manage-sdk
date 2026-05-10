// Package exec provides command execution utilities for Linux system management.
//
// It wraps the go-cmd library to provide buffered and streaming command execution
// with privilege-escalation support (sudo or doas, selectable via
// SetPrivilegeBackend), context cancellation, and output truncation.
package exec

// MaxOutputBytes is the maximum number of bytes captured per output stream.
const MaxOutputBytes = 1 << 20 // 1 MiB

// Result holds the output of a command execution.
type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// StreamType identifies which standard stream a line of streaming
// output came from. Values are numerically stable across SDK releases
// — callers checking `streamType == StreamStdout` are expected to keep
// working without recompilation — and the named type lets the compiler
// reject a stray `int` literal where the contract is "stdout or stderr".
//
// OutputCallback's signature still accepts an `int` for backward source
// compatibility with callers that wrote `func(streamType int, ...)`.
// New code should write `func(streamType StreamType, ...)` and rely on
// the implicit conversion at the call site.
type StreamType int

const (
	// StreamStdout is the streamType passed to OutputCallback for
	// stdout lines.
	StreamStdout StreamType = 1
	// StreamStderr is the streamType passed to OutputCallback for
	// stderr lines.
	StreamStderr StreamType = 2
)

// OutputCallback is called for each line of output during streaming execution.
// streamType: StreamStdout or StreamStderr.
// line: the output line (with newline).
// seq: sequence number for ordering.
type OutputCallback func(streamType int, line string, seq int64)
