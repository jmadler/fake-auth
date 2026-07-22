package logging

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// RequestIDHeader is the header to check for incoming request ID (e.g. X-Request-ID).
const RequestIDHeader = "X-Request-ID"

// Middleware extracts or generates request_id and adds it to the request context.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get(RequestIDHeader))
		if id == "" {
			id = uuid.New().String()
		}
		ctx := WithRequestID(r.Context(), id)
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
