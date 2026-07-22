package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jmadler/auth2/internal/store"
)

func scimTestStore(t *testing.T) store.Store {
	st, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestHandler_ResourceTypes(t *testing.T) {
	st := scimTestStore(t)
	h := NewHandler(st, "https://auth.example.com")
	req := httptest.NewRequest("GET", "/scim/v2/ResourceTypes", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ResourceTypes: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "User") {
		t.Error("ResourceTypes should include User")
	}
}

func TestHandler_Schemas(t *testing.T) {
	st := scimTestStore(t)
	h := NewHandler(st, "https://auth.example.com")
	req := httptest.NewRequest("GET", "/scim/v2/Schemas", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Schemas: want 200, got %d", rec.Code)
	}
}

func TestHandler_ListUsers(t *testing.T) {
	st := scimTestStore(t)
	_ = st.CreateUser(context.Background(), &store.User{
		ID: "u1", Email: "a@test.com", DisplayName: "A",
		OrganizationID: 1, EnterpriseID: 1, Role: "user",
	}, "pass123")
	h := NewHandler(st, "https://auth.example.com")
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ListUsers: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp ListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalResults != 1 {
		t.Errorf("TotalResults want 1, got %d", resp.TotalResults)
	}
}

func TestHandler_CreateUser(t *testing.T) {
	os.Setenv("PASSWORD_POLICY_MIN_LENGTH", "6")
	defer os.Unsetenv("PASSWORD_POLICY_MIN_LENGTH")

	st := scimTestStore(t)
	h := NewHandler(st, "https://auth.example.com")
	body := `{"userName":"newuser@example.com","name":{"givenName":"New","familyName":"User"},"password":"ChangeMe123!"}`
	req := httptest.NewRequest("POST", "/scim/v2/Users", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", ContentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("CreateUser: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	users, _, _ := st.ListUsers(context.Background(), store.ListUsersOpts{})
	if len(users) != 1 {
		t.Errorf("want 1 user created, got %d", len(users))
	}
}

func TestHandler_GetUser_NotFound(t *testing.T) {
	st := scimTestStore(t)
	h := NewHandler(st, "https://auth.example.com")
	req := httptest.NewRequest("GET", "/scim/v2/Users/nonexistent", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GetUser nonexistent: want 404, got %d", rec.Code)
	}
}

func TestHandler_ListGroups(t *testing.T) {
	st := scimTestStore(t)
	h := NewHandler(st, "https://auth.example.com")
	req := httptest.NewRequest("GET", "/scim/v2/Groups", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ListGroups: want 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	os.Unsetenv("SCIM_API_TOKEN")
	os.Unsetenv("ADMIN_API_KEY")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := AuthMiddleware(next)
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// No token configured: allow (dev mode)
	if rec.Code != http.StatusOK {
		t.Errorf("no token configured: want 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_InvalidBearer(t *testing.T) {
	os.Setenv("SCIM_API_TOKEN", "secret123")
	defer os.Unsetenv("SCIM_API_TOKEN")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := AuthMiddleware(next)
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("invalid bearer: want 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_ValidBearer(t *testing.T) {
	os.Setenv("SCIM_API_TOKEN", "secret123")
	defer os.Unsetenv("SCIM_API_TOKEN")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := AuthMiddleware(next)
	req := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("valid bearer: want 200, got %d", rec.Code)
	}
}
