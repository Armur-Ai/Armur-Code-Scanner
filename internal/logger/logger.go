package logger

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

var log zerolog.Logger

func init() {
	level := zerolog.InfoLevel
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		switch strings.ToLower(lvl) {
		case "debug":
			level = zerolog.DebugLevel
		case "warn":
			level = zerolog.WarnLevel
		case "error":
			level = zerolog.ErrorLevel
		case "trace":
			level = zerolog.TraceLevel
		}
	}

	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}

	log = zerolog.New(output).Level(level).With().Timestamp().Logger()
}

// Get returns the global logger instance.
func Get() *zerolog.Logger {
	return &log
}

// Debug logs a debug-level message.
func Debug() *zerolog.Event {
	return log.Debug()
}

// Info logs an info-level message.
func Info() *zerolog.Event {
	return log.Info()
}

// Warn logs a warn-level message.
func Warn() *zerolog.Event {
	return log.Warn()
}

// Error logs an error-level message.
func Error() *zerolog.Event {
	return log.Error()
}

// Fatal logs a fatal-level message and exits.
func Fatal() *zerolog.Event {
	return log.Fatal()
}

// With returns a context logger with the given fields pre-set.
func With() zerolog.Context {
	return log.With()
}
