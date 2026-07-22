package cors

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestMiddleware_NoOrigin(t *testing.T) {
	os.Unsetenv("CORS_ALLOWED_ORIGINS")
	defer os.Unsetenv("CORS_ALLOWED_ORIGINS")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(nil)(next)

	req := httptest.NewRequest("GET", "/oauth/token", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("should set Allow-Methods")
	}
}

func TestMiddleware_WithOrigin(t *testing.T) {
	os.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://app.example.com")
	defer os.Unsetenv("CORS_ALLOWED_ORIGINS")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(nil)(next)

	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if want := "http://localhost:3000"; rec.Header().Get("Access-Control-Allow-Origin") != want {
		t.Errorf("Allow-Origin = %q, want %q", rec.Header().Get("Access-Control-Allow-Origin"), want)
	}
}

func TestMiddleware_OriginNotAllowed(t *testing.T) {
	os.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
	defer os.Unsetenv("CORS_ALLOWED_ORIGINS")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(nil)(next)

	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("disallowed origin should not get Allow-Origin header")
	}
}

func TestMiddleware_Options(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(nil)(next)

	req := httptest.NewRequest("OPTIONS", "/oauth/token", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS status %d, want 204", rec.Code)
	}
	// next handler should not be called
}

func TestMiddleware_OriginsProvider(t *testing.T) {
	os.Setenv("CORS_ALLOWED_ORIGINS", "http://a.com")
	defer os.Unsetenv("CORS_ALLOWED_ORIGINS")

	provider := func() []string { return []string{"http://b.com"} }
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(provider)(next)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://b.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://b.com" {
		t.Errorf("Allow-Origin = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestParseAllowedOrigins_Default(t *testing.T) {
	os.Unsetenv("CORS_ALLOWED_ORIGINS")
	origins := parseAllowedOrigins()
	if len(origins) == 0 {
		t.Error("default should have origins")
	}
	found := false
	for _, o := range origins {
		if o == "http://localhost:3000" {
			found = true
			break
		}
	}
	if !found {
		t.Error("default should include localhost:3000")
	}
}

func TestParseAllowedOrigins_Wildcard(t *testing.T) {
	os.Setenv("CORS_ALLOWED_ORIGINS", "*")
	defer os.Unsetenv("CORS_ALLOWED_ORIGINS")
	origins := parseAllowedOrigins()
	if len(origins) != 1 || origins[0] != "*" {
		t.Errorf("origins = %v", origins)
	}
}
