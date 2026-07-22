package cors

import (
	"net/http"
	"os"
	"strings"
)

// Default localhost origins for dev when CORS_ALLOWED_ORIGINS is unset.
var defaultOrigins = []string{
	"http://localhost",
	"http://localhost:3000",
	"http://localhost:9092",
	"http://127.0.0.1",
	"http://127.0.0.1:3000",
	"http://127.0.0.1:9092",
}

// Middleware returns CORS middleware that sets Access-Control-* headers
// based on CORS_ALLOWED_ORIGINS env or default localhost origins.
// OriginsProvider can optionally supply additional origins (e.g. from client registry).
func Middleware(originsProvider func() []string) func(http.Handler) http.Handler {
	allowed := parseAllowedOrigins()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origins := append([]string{}, allowed...)
			if originsProvider != nil {
				seen := make(map[string]bool)
				for _, o := range origins {
					seen[o] = true
				}
				for _, o := range originsProvider() {
					o = strings.TrimSpace(o)
					if o != "" && !seen[o] {
						origins = append(origins, o)
						seen[o] = true
					}
				}
			}
			reqOrigin := r.Header.Get("Origin")
			acAllowOrigin := ""
			if reqOrigin != "" {
				for _, o := range origins {
					if o == "*" || o == reqOrigin {
						acAllowOrigin = o
						break
					}
				}
			}
			if acAllowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", acAllowOrigin)
			}
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PATCH")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func parseAllowedOrigins() []string {
	raw := os.Getenv("CORS_ALLOWED_ORIGINS")
	if raw == "" {
		return append([]string{}, defaultOrigins...)
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	return out
}
