package securityheaders

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_WithoutTLS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(false)(next)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options")
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS should be empty when useTLS=false")
	}
}

func TestMiddleware_WithTLS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(true)(next)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS should be set when useTLS=true")
	}
	if hsts != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS = %q", hsts)
	}
}
