package adminui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHandler_DevMode(t *testing.T) {
	h := NewHandler(Config{AdminAPIKey: "", ProductionMode: false})

	// /admin/login should be accessible without auth
	req := httptest.NewRequest("GET", "/admin/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusFound {
		t.Errorf("GET /admin/login: %d", rec.Code)
	}
}

func TestNewHandler_NotFound(t *testing.T) {
	h := NewHandler(Config{})

	req := httptest.NewRequest("GET", "/not-admin", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("non-admin path: %d", rec.Code)
	}
}

func TestNewHandler_AdminWithAuth(t *testing.T) {
	h := NewHandler(Config{AdminAPIKey: "secret-key", ProductionMode: false})

	// Without cookie: redirect to login
	req := httptest.NewRequest("GET", "/admin/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("unauthenticated: %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/admin/login" {
		t.Errorf("Location = %q", loc)
	}
}

func TestNewHandler_PostLogin(t *testing.T) {
	h := NewHandler(Config{AdminAPIKey: "mykey", ProductionMode: false})

	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader("key=mykey"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("login: %d", rec.Code)
	}
	if rec.Header().Get("Location") != "/admin/" {
		t.Errorf("Location = %q", rec.Header().Get("Location"))
	}
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == adminKeyCookie && c.Value == "mykey" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected admin key cookie")
	}
}
