package adminauth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jmadler/auth2/internal/token"
)

func TestMiddleware_DevModeAllowsUnauthenticated(t *testing.T) {
	issuer, err := token.NewIssuer("http://test/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{AdminAPIKey: "", ProductionMode: false, Issuer: issuer}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mw := Middleware(cfg)(handler)

	req := httptest.NewRequest("GET", "/api/v2/users", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("dev mode: want 200, got %d", rec.Code)
	}
}

func TestMiddleware_RequiresAuthWhenAdminKeySet(t *testing.T) {
	issuer, _ := token.NewIssuer("http://test/")
	cfg := Config{AdminAPIKey: "secret-key", ProductionMode: false, Issuer: issuer}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := Middleware(cfg)(handler)

	req := httptest.NewRequest("GET", "/api/v2/users", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no auth: want 401, got %d", rec.Code)
	}
}

func TestMiddleware_AcceptsBearerKey(t *testing.T) {
	issuer, _ := token.NewIssuer("http://test/")
	cfg := Config{AdminAPIKey: "secret-key", ProductionMode: false, Issuer: issuer}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := Middleware(cfg)(handler)

	req := httptest.NewRequest("GET", "/api/v2/users", nil)
	req.Header.Set("Authorization", "Bearer secret-key")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("valid key: want 200, got %d", rec.Code)
	}
}

func TestMiddleware_ExemptsHealthAndWellKnown(t *testing.T) {
	cfg := Config{AdminAPIKey: "secret", ProductionMode: true, Issuer: nil}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := Middleware(cfg)(handler)

	tests := []struct {
		path string
		want int
	}{
		{"/health", 200},
		{"/.well-known/jwks.json", 200},
		{"/.well-known/openid-configuration", 200},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%s: want %d, got %d", tt.path, tt.want, rec.Code)
		}
	}
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("ADMIN_API_KEY", "key1")
	defer os.Unsetenv("ADMIN_API_KEY")
	os.Unsetenv("MGMT_API_KEY")
	os.Unsetenv("PRODUCTION_MODE")

	cfg := LoadFromEnv(nil)
	if cfg.AdminAPIKey != "key1" {
		t.Errorf("AdminAPIKey want key1, got %q", cfg.AdminAPIKey)
	}
	if cfg.ProductionMode {
		t.Error("ProductionMode should be false when unset")
	}

	os.Unsetenv("ADMIN_API_KEY")
	os.Setenv("MGMT_API_KEY", "key2")
	defer os.Unsetenv("MGMT_API_KEY")
	cfg = LoadFromEnv(nil)
	if cfg.AdminAPIKey != "key2" {
		t.Errorf("MGMT_API_KEY: want key2, got %q", cfg.AdminAPIKey)
	}
}
