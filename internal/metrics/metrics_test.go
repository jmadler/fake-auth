package metrics // white-box to test sanitizePath

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(next)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status %d", rec.Code)
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"/api/v2/users/auth0|123", "/api/v2/users/:id"},
		{"/api/v2/users/abc", "/api/v2/users/:id"},
		{"/api/v2/clients/e2e-test", "/api/v2/clients/:id"},
		{"/api/v2/roles/rol_admin", "/api/v2/roles/:id"},
		{"/api/v2/connections/con_db", "/api/v2/connections/:id"},
		{"/health", "/health"},
		{"/oauth/token", "/oauth/token"},
		{"/api/v2/users/", "/api/v2/users"}, // TrimSuffix removes trailing /
	}
	for _, tt := range tests {
		got := sanitizePath(tt.in)
		if got != tt.want {
			t.Errorf("sanitizePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
