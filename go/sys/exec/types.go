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

// OutputCallback is called for each line of output during streaming execution.
// streamType: 1 = stdout, 2 = stderr.
// line: the output line (with newline).
// seq: sequence number for ordering.
type OutputCallback func(streamType int, line string, seq int64)
