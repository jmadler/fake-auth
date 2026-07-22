package tracing

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

const serviceName = "auth2"

var (
	provider   *sdktrace.TracerProvider
	providerMu sync.Mutex
)

// Init initializes the OpenTelemetry tracer when OTEL_EXPORTER_OTLP_ENDPOINT is set.
// If not set, tracing is a no-op (otel.GetTracerProvider returns a no-op provider).
func Init(ctx context.Context) error {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if endpoint == "" {
		return nil
	}

	providerMu.Lock()
	defer providerMu.Unlock()

	if provider != nil {
		return nil
	}

	// OTLP HTTP exporter reads OTEL_EXPORTER_OTLP_ENDPOINT from env when not passed.
	// We pass WithEndpoint to use our validated endpoint; WithInsecure for http://.
	var opts []otlptracehttp.Option
	if strings.HasPrefix(endpoint, "http://") {
		opts = append(opts, otlptracehttp.WithInsecure())
		// WithEndpoint expects host:port; strip scheme
		endpoint = strings.TrimPrefix(endpoint, "http://")
	} else if strings.HasPrefix(endpoint, "https://") {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	}
	if idx := strings.Index(endpoint, "/"); idx >= 0 {
		endpoint = endpoint[:idx]
	}
	opts = append(opts, otlptracehttp.WithEndpoint(endpoint))

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return err
	}

	provider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(provider)
	return nil
}

// Shutdown flushes and shuts down the tracer provider. Call on graceful shutdown.
func Shutdown(ctx context.Context) error {
	providerMu.Lock()
	defer providerMu.Unlock()
	if provider == nil {
		return nil
	}
	err := provider.Shutdown(ctx)
	provider = nil
	return err
}

// Middleware wraps an HTTP handler to create a span per request.
// Traces /authorize, /oauth/token, /login with span attributes: path, method, user_id, client_id.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracer := otel.Tracer(serviceName)
		ctx, span := tracer.Start(r.Context(), spanName(r))
		defer span.End()

		span.SetAttributes(
			attribute.String("http.method", r.Method),
			attribute.String("http.url.path", r.URL.Path),
		)

		if uid := r.URL.Query().Get("user_id"); uid != "" {
			span.SetAttributes(attribute.String("auth2.user_id", uid))
		}
		if cid := r.URL.Query().Get("client_id"); cid != "" {
			span.SetAttributes(attribute.String("auth2.client_id", cid))
		}
		if err := r.ParseForm(); err == nil {
			if uid := r.Form.Get("user_id"); uid != "" {
				span.SetAttributes(attribute.String("auth2.user_id", uid))
			}
			if cid := r.Form.Get("client_id"); cid != "" {
				span.SetAttributes(attribute.String("auth2.client_id", cid))
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func spanName(r *http.Request) string {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "" {
		path = "/"
	}
	return r.Method + " " + path
}
