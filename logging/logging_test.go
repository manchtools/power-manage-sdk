package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseLevel(tt.input)
			if got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSetupLogger_JSON(t *testing.T) {
	var buf bytes.Buffer
	logger := SetupLogger("info", "json", &buf)

	logger.Info("test message", "key", "value")

	output := buf.String()
	if !strings.Contains(output, `"msg":"test message"`) {
		t.Errorf("expected JSON output with msg field, got: %s", output)
	}
	if !strings.Contains(output, `"key":"value"`) {
		t.Errorf("expected JSON output with key field, got: %s", output)
	}
}

func TestSetupLogger_Text(t *testing.T) {
	var buf bytes.Buffer
	logger := SetupLogger("info", "text", &buf)

	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected text output with message, got: %s", output)
	}
}

func TestSetupLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := SetupLogger("warn", "text", &buf)

	logger.Info("should not appear")
	if buf.Len() > 0 {
		t.Errorf("info message should be filtered at warn level, got: %s", buf.String())
	}

	logger.Warn("should appear")
	if buf.Len() == 0 {
		t.Error("warn message should not be filtered at warn level")
	}
}
