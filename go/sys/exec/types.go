// Package exec provides command execution utilities for Linux system management.
//
// It wraps the go-cmd library to provide buffered and streaming command execution
// with sudo support, context cancellation, and output truncation.
package exec

// MaxOutputBytes is the maximum number of bytes captured per output stream.
const MaxOutputBytes = 1 << 20 // 1 MiB

// Result holds the output of a command execution.
type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// Stream identifiers passed to OutputCallback. The values must
// stay numerically stable across SDK releases: callers checking
// `streamType == StreamStdout` are expected to keep working
// without recompilation. Use these constants instead of the
// literal 1/2 magic numbers.
const (
	// StreamStdout is the streamType passed to OutputCallback for
	// stdout lines.
	StreamStdout = 1
	// StreamStderr is the streamType passed to OutputCallback for
	// stderr lines.
	StreamStderr = 2
)

// OutputCallback is called for each line of output during streaming execution.
// streamType: StreamStdout or StreamStderr.
// line: the output line (with newline).
// seq: sequence number for ordering.
type OutputCallback func(streamType int, line string, seq int64)
