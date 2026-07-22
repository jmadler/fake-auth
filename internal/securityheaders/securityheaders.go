package securityheaders

import (
	"net/http"
)

// Middleware adds security headers to responses.
// When useTLS is true, adds Strict-Transport-Security.
func Middleware(useTLS bool) func(http.Handler) http.Handler {
	hsts := ""
	if useTLS {
		hsts = "max-age=31536000; includeSubDomains"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			if hsts != "" {
				w.Header().Set("Strict-Transport-Security", hsts)
			}
			next.ServeHTTP(w, r)
		})
	}
}
