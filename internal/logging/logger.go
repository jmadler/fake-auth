package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

const (
	KeyRequestID = "request_id"
	KeyUserID    = "user_id"
	KeyClientID  = "client_id"
	KeyError     = "error"
)

// contextKey type for request_id in context.
type contextKey string

const requestIDKey contextKey = "request_id"

// Init configures the default logger from env.
// LOG_FORMAT=json|text (default text for dev).
func Init() {
	format := strings.ToLower(os.Getenv("LOG_FORMAT"))
	if format == "json" {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})))
	}
}

// WithRequestID returns ctx with request_id stored.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext returns the request_id from ctx, or empty string.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// Log logs at the given level with standard fields from ctx plus any extras.
// args are key-value pairs: Log(ctx, level, msg, "user_id", "x", "error", err)
func Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	out := make([]any, 0, len(args)+2)
	if id := RequestIDFromContext(ctx); id != "" {
		out = append(out, KeyRequestID, id)
	}
	out = append(out, args...)
	logger := slog.Default()
	switch level {
	case slog.LevelDebug:
		logger.DebugContext(ctx, msg, out...)
	case slog.LevelInfo:
		logger.InfoContext(ctx, msg, out...)
	case slog.LevelWarn:
		logger.WarnContext(ctx, msg, out...)
	case slog.LevelError:
		logger.ErrorContext(ctx, msg, out...)
	default:
		logger.InfoContext(ctx, msg, out...)
	}
}

// Info logs at info level.
func Info(ctx context.Context, msg string, args ...any) { Log(ctx, slog.LevelInfo, msg, args...) }

// Warn logs at warn level.
func Warn(ctx context.Context, msg string, args ...any) { Log(ctx, slog.LevelWarn, msg, args...) }

// Error logs at error level.
func Error(ctx context.Context, msg string, args ...any) { Log(ctx, slog.LevelError, msg, args...) }

// Debug logs at debug level.
func Debug(ctx context.Context, msg string, args ...any) { Log(ctx, slog.LevelDebug, msg, args...) }
