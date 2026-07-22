package metrics

import (
	"net/http"
	"strings"
	"time"
)

// Middleware records request duration (auth2_request_duration_seconds) for each request.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		path := sanitizePath(r.URL.Path)
		ObserveRequestDuration(path, r.Method, time.Since(start))
	})
}

// sanitizePath reduces cardinality by replacing IDs with placeholders.
func sanitizePath(p string) string {
	p = strings.TrimSuffix(p, "/")
	if strings.HasPrefix(p, "/api/v2/users/") && len(p) > 13 {
		return "/api/v2/users/:id"
	}
	if strings.HasPrefix(p, "/api/v2/clients/") && len(p) > 14 {
		return "/api/v2/clients/:id"
	}
	if strings.HasPrefix(p, "/api/v2/roles/") && len(p) > 12 {
		return "/api/v2/roles/:id"
	}
	if strings.HasPrefix(p, "/api/v2/connections/") && len(p) > 18 {
		return "/api/v2/connections/:id"
	}
	return p
}
