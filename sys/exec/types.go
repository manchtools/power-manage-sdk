// Package exec provides command execution utilities for Linux system management.
//
// It wraps the go-cmd library to provide buffered and streaming command execution
// with privilege escalation, context cancellation, and output truncation.
//
// Command execution goes through the injected Runner: build one with
// NewRunner(Sudo|Doas|Direct) (Detect lists the escalation tools available on
// the host) and pass it to a capability constructor. The Runner carries no
// global state and is unit-testable with exectest.FakeRunner. The legacy
// process-global path (Run*/Privileged*/Query* and the SetPrivilegeBackend
// global) was removed once every capability migrated onto the Runner.
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
// output came from. The named type lets the compiler reject a stray
// `int` literal where the contract is "stdout or stderr". Numeric
// values are stable across SDK releases.
type StreamType int

const (
	// StreamStdout is the streamType passed to OutputCallback for
	// stdout lines.
	StreamStdout StreamType = 1
	// StreamStderr is the streamType passed to OutputCallback for
	// stderr lines.
	StreamStderr StreamType = 2
)

// OutputCallback is called for each line of output during streaming
// execution. streamType is the typed StreamType (Go's type system
// rejects implicit int↔StreamType conversion, so taking int here would
// mean every comparison needed an explicit cast). line is the output
// line including its trailing newline. seq is a stream-local
// monotonic ordering counter.
type OutputCallback func(streamType StreamType, line string, seq int64)
