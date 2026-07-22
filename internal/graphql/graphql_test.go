package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jmadler/auth2/internal/store"
)

func TestGraphQLHandler_CreateUser(t *testing.T) {
	os.Setenv("ADMIN_API_KEY", "test-admin-key")
	os.Setenv("GRAPHQL_TEST_API_ENABLED", "true")
	defer func() {
		os.Unsetenv("ADMIN_API_KEY")
		os.Unsetenv("GRAPHQL_TEST_API_ENABLED")
	}()

	st, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer st.Close()

	h := Handler(st)
	body := `{"query":"mutation { createUser(email: \"gqluser@example.com\", password: \"SecurePass123!\", name: \"GQL User\") { id email name } }"}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if errs, ok := result["errors"]; ok && errs != nil {
		t.Errorf("unexpected errors: %v", errs)
	}
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		t.Errorf("no data in response: %v", result)
	}
	createUser, ok := data["createUser"].(map[string]interface{})
	if !ok {
		t.Errorf("no createUser in data: %v", data)
	}
	if createUser["email"] != "gqluser@example.com" {
		t.Errorf("email = %v", createUser["email"])
	}

	// Verify user exists in store
	u, err := st.GetByEmail(context.Background(), "gqluser@example.com")
	if err != nil || u == nil {
		t.Errorf("user not found in store: %v", err)
	}
}

func TestGraphQLHandler_Unauthorized(t *testing.T) {
	os.Setenv("ADMIN_API_KEY", "secret")
	os.Setenv("GRAPHQL_TEST_API_ENABLED", "true")
	defer func() {
		os.Unsetenv("ADMIN_API_KEY")
		os.Unsetenv("GRAPHQL_TEST_API_ENABLED")
	}()

	st, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer st.Close()

	h := Handler(st)
	body := `{"query":"mutation { createUser(email: \"x@x.com\", password: \"Pass123!\") { id } }"}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestGraphQLHandler_InvalidPassword(t *testing.T) {
	os.Setenv("ADMIN_API_KEY", "test-key")
	os.Setenv("GRAPHQL_TEST_API_ENABLED", "true")
	defer func() {
		os.Unsetenv("ADMIN_API_KEY")
		os.Unsetenv("GRAPHQL_TEST_API_ENABLED")
	}()

	st, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer st.Close()

	h := Handler(st)
	body := `{"query":"mutation { createUser(email: \"x@x.com\", password: \"short\") { id } }"}`
	req := httptest.NewRequest("POST", "/graphql", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
	var result map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&result)
	if errs, ok := result["errors"]; !ok || errs == nil {
		t.Error("expected errors for weak password")
	}
}

func TestIsEnabled(t *testing.T) {
	os.Unsetenv("GRAPHQL_TEST_API_ENABLED")
	if IsEnabled() {
		t.Error("IsEnabled should be false when unset")
	}
	os.Setenv("GRAPHQL_TEST_API_ENABLED", "true")
	defer os.Unsetenv("GRAPHQL_TEST_API_ENABLED")
	if !IsEnabled() {
		t.Error("IsEnabled should be true")
	}
}
