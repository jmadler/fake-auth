package logging

import (
	"context"
	"log/slog"
	"testing"
)

func TestWithRequestID(t *testing.T) {
	ctx := context.Background()
	ctx2 := WithRequestID(ctx, "req-123")
	if ctx2 == ctx {
		t.Error("WithRequestID should return new context")
	}
}

func TestRequestIDFromContext(t *testing.T) {
	ctx := context.Background()
	if got := RequestIDFromContext(ctx); got != "" {
		t.Errorf("empty ctx: got %q", got)
	}
	ctx = WithRequestID(ctx, "req-456")
	if got := RequestIDFromContext(ctx); got != "req-456" {
		t.Errorf("got %q, want req-456", got)
	}
}

func TestLog_NoPanic(t *testing.T) {
	ctx := context.Background()
	Log(ctx, slog.LevelInfo, "test message")
	Info(ctx, "info message")
	Warn(ctx, "warn message")
	Error(ctx, "error message", KeyError, "test err")
	Debug(ctx, "debug message")
	// With request ID
	ctx = WithRequestID(ctx, "r1")
	Info(ctx, "with id", "key", "value")
}
