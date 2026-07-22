package scim

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// AuthMiddleware returns a handler that requires Bearer token for SCIM routes.
// Token is accepted from SCIM_API_TOKEN, SCIM_BEARER_TOKEN, or ADMIN_API_KEY (fallback).
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := tokenFromEnv()
		if token == "" {
			// No token configured: allow (dev mode, same as management API)
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			sendSCIMUnauthorized(w, "Missing or invalid Authorization header")
			return
		}
		bearer := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if bearer != token {
			sendSCIMUnauthorized(w, "Invalid SCIM bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tokenFromEnv() string {
	if v := os.Getenv("SCIM_API_TOKEN"); v != "" {
		return v
	}
	if v := os.Getenv("SCIM_BEARER_TOKEN"); v != "" {
		return v
	}
	if v := os.Getenv("ADMIN_API_KEY"); v != "" {
		return v
	}
	if v := os.Getenv("MGMT_API_KEY"); v != "" {
		return v
	}
	return ""
}

func sendSCIMUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+msg+`"`)
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":   msg,
		"status":   "401",
	})
}
