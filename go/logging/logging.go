package logging

import (
	"io"
	"log/slog"
)

// ParseLevel converts a level string to slog.Level.
// Supported values: "debug", "info", "warn", "error". Defaults to slog.LevelInfo.
func ParseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// SetupLogger creates a new slog.Logger with the given level, format, and output.
// Format "json" produces JSON output; anything else produces text output.
func SetupLogger(level, format string, output io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: ParseLevel(level)}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(output, opts)
	} else {
		handler = slog.NewTextHandler(output, opts)
	}

	return slog.New(handler)
}
