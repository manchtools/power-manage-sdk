package exec

// EndOfOptions is the conventional getopt/popt "--" token that tells a CLI
// to stop parsing options: every argument after it is an operand, even one
// that begins with "-". Place it immediately before positional arguments
// whose values aren't fixed literals (a username, device path, package
// name, notification title, …) so a value shaped like a flag can never be
// reinterpreted as one.
const EndOfOptions = "--"

// SeparatePositionals returns flags, then a single EndOfOptions marker,
// then the positionals — the fail-safe argv shape for any tool that
// honours "--" (useradd, usermod, groupadd, userdel, mount, shutdown,
// notify-send, …). It guarantees a flag-shaped positional is treated as an
// operand without relying on each caller's input validation. The result is
// a freshly allocated slice; the caller's flags slice is never mutated.
func SeparatePositionals(flags []string, positionals ...string) []string {
	out := make([]string, 0, len(flags)+1+len(positionals))
	out = append(out, flags...)
	out = append(out, EndOfOptions)
	out = append(out, positionals...)
	return out
}
