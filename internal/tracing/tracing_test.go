package tracing

import (
	"context"
	"os"
	"testing"
)

func TestInit_NoEndpoint(t *testing.T) {
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	err := Init(context.Background())
	if err != nil {
		t.Errorf("Init with no endpoint: %v", err)
	}
}

func TestInit_EmptyEndpoint(t *testing.T) {
	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	defer os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	err := Init(context.Background())
	if err != nil {
		t.Errorf("Init: %v", err)
	}
}
