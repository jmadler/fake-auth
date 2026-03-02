package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmadler/fake-auth/internal/clients"
	"github.com/jmadler/fake-auth/internal/grants"
	"github.com/jmadler/fake-auth/internal/rules"
	"github.com/jmadler/fake-auth/internal/sessions"
	"github.com/jmadler/fake-auth/internal/store"
	"github.com/jmadler/fake-auth/internal/token"
)

func testHandlers(t *testing.T) *Handlers {
	st, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	u := &store.User{ID: "auth0|test-user", Email: "test@example.com", DisplayName: "Test User", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(context.Background(), u, "password123"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	issuer, err := token.NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	grantStore := grants.NewStore(5*time.Minute, 24*time.Hour)
	return &Handlers{Store: st, Issuer: issuer, IssuerURL: "https://test.example.com", GrantStore: grantStore, ClientRegistry: clients.NewRegistry()}
}

func (h *Handlers) do(t *testing.T, method, path string, body io.Reader, contentType string) *http.Response {
	req := httptest.NewRequest(method, "https://test.example.com"+path, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func (h *Handlers) doForm(t *testing.T, method, path string, form url.Values) *http.Response {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, "https://test.example.com"+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func (h *Handlers) doFormWithCookies(t *testing.T, method, path string, form url.Values, cookies []*http.Cookie) *http.Response {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, "https://test.example.com"+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func (h *Handlers) doWithCookies(t *testing.T, method, path string, body io.Reader, contentType string, cookies []*http.Cookie) *http.Response {
	req := httptest.NewRequest(method, "https://test.example.com"+path, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func testHandlersWithSessionStore(t *testing.T) *Handlers {
	h := testHandlers(t)
	h.SessionStore = sessions.NewStore(24 * time.Hour)
	return h
}

func TestHealth(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/health", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var out map[string]string
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "ok" {
		t.Errorf("status = %q, want ok", out["status"])
	}
}

func TestMetrics(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/metrics", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "authorize") && !strings.Contains(string(body), "fake_auth") {
		t.Errorf("expected Prometheus metrics containing authorize or fake_auth")
	}
}

func TestPasswordGrant(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("client_id", "my-client")
	resp := h.doForm(t, "POST", "/oauth/token", form)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["access_token"].(string); !ok {
		t.Errorf("missing access_token: %v", out)
	}
}

func TestPasswordGrantWrongPassword(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "wrong")
	resp := h.doForm(t, "POST", "/oauth/token", form)
	if resp.StatusCode != 400 {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestPasswordGrantWithOpenIDScope(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("scope", "openid profile email")
	resp := h.doForm(t, "POST", "/oauth/token", form)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if _, ok := out["id_token"].(string); !ok {
		t.Errorf("expected id_token with openid scope: %v", out)
	}
}

func TestClientCredentials(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "api-client")
	resp := h.doForm(t, "POST", "/oauth/token", form)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if _, ok := out["access_token"].(string); !ok {
		t.Errorf("missing access_token: %v", out)
	}
}

func TestUserinfo(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	accessTok := tokOut["access_token"].(string)

	req := httptest.NewRequest("GET", "https://test.example.com/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("userinfo status %d: %s", resp.StatusCode, b)
	}
	var user map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&user)
	if user["sub"] != "auth0|test-user" {
		t.Errorf("sub = %v", user["sub"])
	}
	if user["email"] != "test@example.com" {
		t.Errorf("email = %v", user["email"])
	}
}

func TestUserinfoNoAuth(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/userinfo", nil, "")
	if resp.StatusCode != 401 {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
}

func TestTokeninfo(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("scope", "openid")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	idTok := tokOut["id_token"].(string)

	form2 := url.Values{}
	form2.Set("id_token", idTok)
	resp := h.doForm(t, "POST", "/tokeninfo", form2)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("tokeninfo status %d: %s", resp.StatusCode, b)
	}
	var info map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&info)
	if info["sub"] != "auth0|test-user" {
		t.Errorf("sub = %v", info["sub"])
	}
}

func TestAuthorizeWithCredentials(t *testing.T) {
	h := testHandlers(t)
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=code&client_id=myclient&redirect_uri=http://localhost/callback&state=xyz&username=test@example.com&password=password123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://localhost/callback") {
		t.Errorf("Location = %s", loc)
	}
	parsed, _ := url.Parse(loc)
	code := parsed.Query().Get("code")
	state := parsed.Query().Get("state")
	if code == "" {
		t.Error("missing code in redirect")
	}
	if state != "xyz" {
		t.Errorf("state = %q, want xyz", state)
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", "myclient")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	if tokResp.StatusCode != 200 {
		b, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("token exchange status %d: %s", tokResp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&out)
	if _, ok := out["access_token"].(string); !ok {
		t.Errorf("missing access_token: %v", out)
	}
}

func TestAuthorizeInvalidCredentials(t *testing.T) {
	h := testHandlers(t)
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&username=test@example.com&password=wrong", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302 redirect to error", resp.StatusCode)
	}
	parsed, _ := url.Parse(resp.Header.Get("Location"))
	if parsed.Query().Get("error") != "access_denied" {
		t.Errorf("expected error=access_denied, got %v", parsed.Query())
	}
}

func TestSessionFlow(t *testing.T) {
	h := testHandlersWithSessionStore(t)
	// 1. POST /login with credentials to get session cookie
	form := url.Values{}
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("client_id", "c")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("scope", "openid")
	form.Set("state", "s1")
	form.Set("response_type", "code")
	loginResp := h.doForm(t, "POST", "/login", form)
	if loginResp.StatusCode != 302 {
		b, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("login status %d: %s", loginResp.StatusCode, b)
	}
	var sessionCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie from login")
	}
	// 2. GET /authorize without username/password but with cookie — should redirect with code
	authResp := h.doWithCookies(t, "GET", "/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/callback&state=s2", nil, "", []*http.Cookie{sessionCookie})
	if authResp.StatusCode != 302 {
		b, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status %d: %s", authResp.StatusCode, b)
	}
	loc := authResp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://localhost/callback") {
		t.Errorf("Location = %s, want redirect to callback", loc)
	}
	parsed, _ := url.Parse(loc)
	if code := parsed.Query().Get("code"); code == "" {
		t.Error("expected code in redirect, got login redirect")
	}
	if parsed.Query().Get("error") != "" {
		t.Errorf("unexpected error in redirect: %s", parsed.Query().Get("error"))
	}
}

func TestClientSecretValidation(t *testing.T) {
	reg := clients.NewRegistry()
	reg.Add("secret-client", &clients.ClientConfig{
		ClientSecret: "correct-secret",
		RedirectURIs:  []string{"http://localhost/callback"},
	})
	reg.RequireSecretForCodes = true

	st, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	u := &store.User{ID: "auth0|test-user", Email: "test@example.com", DisplayName: "Test User", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(context.Background(), u, "password123"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	issuer, _ := token.NewIssuer("https://test.example.com/")
	grantStore := grants.NewStore(5*time.Minute, 24*time.Hour)
	h := &Handlers{Store: st, Issuer: issuer, IssuerURL: "https://test.example.com", GrantStore: grantStore, ClientRegistry: reg}

	// Get auth code with credentials
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=code&client_id=secret-client&redirect_uri=http://localhost/callback&state=s&username=test@example.com&password=password123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 302 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status %d: %s", resp.StatusCode, b)
	}
	parsed, _ := url.Parse(resp.Header.Get("Location"))
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatal("missing code in redirect")
	}

	// Exchange with wrong client_secret -> 400
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", "secret-client")
	form.Set("client_secret", "wrong-secret")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	if tokResp.StatusCode != 400 {
		b, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("expected 400 for wrong client_secret, got %d: %s", tokResp.StatusCode, b)
	}
	var errOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&errOut)
	if errOut["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", errOut["error"])
	}
}

func TestRedirectURIValidation(t *testing.T) {
	reg := clients.NewRegistry()
	reg.Add("redirect-client", &clients.ClientConfig{
		RedirectURIs: []string{"http://localhost/callback"},
	})
	st, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	u := &store.User{ID: "auth0|test-user", Email: "test@example.com", DisplayName: "Test User", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(context.Background(), u, "password123"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	issuer, _ := token.NewIssuer("https://test.example.com/")
	grantStore := grants.NewStore(5*time.Minute, 24*time.Hour)
	h := &Handlers{Store: st, Issuer: issuer, IssuerURL: "https://test.example.com", GrantStore: grantStore, ClientRegistry: reg}

	// authorize with redirect_uri not in allowed list -> 400
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=code&client_id=redirect-client&redirect_uri=http://evil.com/callback&state=s&username=test@example.com&password=password123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 400 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for disallowed redirect_uri, got %d: %s", resp.StatusCode, b)
	}
	var errOut map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&errOut)
	if errOut["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", errOut["error"])
	}
}

func TestRulesInjectClaims(t *testing.T) {
	rulesDir := t.TempDir()
	ruleContent := `u.id_token_claims = u.id_token_claims || {}; u.id_token_claims.custom_claim = "value"; cb(null, u);`
	if err := os.WriteFile(filepath.Join(rulesDir, "add_claim.js"), []byte(ruleContent), 0644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	runner := rules.NewRunner(rulesDir)

	st, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	u := &store.User{ID: "auth0|test-user", Email: "test@example.com", DisplayName: "Test User", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(context.Background(), u, "password123"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	issuer, _ := token.NewIssuer("https://test.example.com/")
	h := &Handlers{Store: st, Issuer: issuer, IssuerURL: "https://test.example.com", RulesRunner: runner}

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("scope", "openid")
	resp := h.doForm(t, "POST", "/oauth/token", form)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("token status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	idTok, ok := out["id_token"].(string)
	if !ok {
		t.Fatal("expected id_token")
	}
	parts := strings.Split(idTok, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Add padding if needed
		switch len(parts[1]) % 4 {
		case 2:
			payload, err = base64.RawURLEncoding.DecodeString(parts[1] + "==")
		case 3:
			payload, err = base64.RawURLEncoding.DecodeString(parts[1] + "=")
		}
	}
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if claims["custom_claim"] != "value" {
		t.Errorf("id_token custom_claim = %v, want value", claims["custom_claim"])
	}
}

func TestScopeValidation(t *testing.T) {
	reg := clients.NewRegistry()
	reg.Add("scope-client", &clients.ClientConfig{
		AllowedScopes: []string{"openid", "profile"},
	})
	st, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	u := &store.User{ID: "auth0|test-user", Email: "test@example.com", DisplayName: "Test User", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(context.Background(), u, "password123"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	issuer, _ := token.NewIssuer("https://test.example.com/")
	grantStore := grants.NewStore(5*time.Minute, 24*time.Hour)
	h := &Handlers{Store: st, Issuer: issuer, IssuerURL: "https://test.example.com", GrantStore: grantStore, ClientRegistry: reg}

	// authorize with scope not in allowed_scopes -> 400
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=code&client_id=scope-client&redirect_uri=http://localhost/cb&scope=openid+forbidden_scope&state=s&username=test@example.com&password=password123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 400 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for disallowed scope, got %d: %s", resp.StatusCode, b)
	}
	var errOut map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&errOut)
	if errOut["error"] != "invalid_scope" {
		t.Errorf("error = %v, want invalid_scope", errOut["error"])
	}
}

func TestRefreshTokenGrant(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("scope", "openid offline_access")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	refreshTok := tokOut["refresh_token"].(string)

	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", refreshTok)
	form2.Set("client_id", "radimal-e2e")
	refreshResp := h.doForm(t, "POST", "/oauth/token", form2)
	if refreshResp.StatusCode != 200 {
		b, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("refresh status %d: %s", refreshResp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(refreshResp.Body).Decode(&out)
	if _, ok := out["access_token"].(string); !ok {
		t.Errorf("missing access_token: %v", out)
	}
	if _, ok := out["refresh_token"].(string); !ok {
		t.Errorf("expected new refresh_token (rotation): %v", out)
	}
}

func TestJWKS(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/.well-known/jwks.json", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(jwks.Keys))
	}
	if kid, ok := jwks.Keys[0]["kid"].(string); !ok || kid == "" {
		t.Errorf("expected kid in JWKS, got %v", jwks.Keys[0]["kid"])
	}
}

func TestIDTokenHasAmrAndSid(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("scope", "openid")
	resp := h.doForm(t, "POST", "/oauth/token", form)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	idTok, ok := out["id_token"].(string)
	if !ok {
		t.Fatal("expected id_token")
	}
	// Decode JWT payload (middle part)
	parts := strings.Split(idTok, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if amr, ok := claims["amr"].([]interface{}); !ok || len(amr) == 0 {
		t.Errorf("expected amr claim: %v", claims["amr"])
	}
	if sid, ok := claims["sid"].(string); !ok || sid == "" {
		t.Errorf("expected sid claim: %v", claims["sid"])
	}
}

func TestAuthCodeFlowWithNonceAtHashCHash(t *testing.T) {
	h := testHandlers(t)
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=code&client_id=myclient&redirect_uri=http://localhost/callback&state=xyz&username=test@example.com&password=password123&nonce=testnonce123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	parsed, _ := url.Parse(resp.Header.Get("Location"))
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatal("missing code in redirect")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", "myclient")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	if tokResp.StatusCode != 200 {
		b, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("token status %d: %s", tokResp.StatusCode, b)
	}
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	idTok, ok := tokOut["id_token"].(string)
	if !ok {
		t.Fatal("expected id_token")
	}
	parts := strings.Split(idTok, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]interface{}
	json.Unmarshal(payload, &claims)
	if nonce, _ := claims["nonce"].(string); nonce != "testnonce123" {
		t.Errorf("nonce = %q, want testnonce123", nonce)
	}
	if _, ok := claims["at_hash"]; !ok {
		t.Error("expected at_hash in id_token")
	}
	if _, ok := claims["c_hash"]; !ok {
		t.Error("expected c_hash in id_token")
	}
}

func TestTokenLifetimeConfig(t *testing.T) {
	h := testHandlers(t)
	h.AccessTokenLifetime = 7200
	h.IDTokenLifetime = 1800
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("scope", "openid")
	resp := h.doForm(t, "POST", "/oauth/token", form)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if exp, ok := out["expires_in"].(float64); !ok || int(exp) != 7200 {
		t.Errorf("expires_in = %v, want 7200", out["expires_in"])
	}
}

func TestOpenIDConfig(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/.well-known/openid-configuration", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var cfg map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&cfg)
	if _, ok := cfg["userinfo_endpoint"].(string); !ok {
		t.Errorf("missing userinfo_endpoint: %v", cfg)
	}
	if _, ok := cfg["authorization_endpoint"].(string); !ok {
		t.Errorf("missing authorization_endpoint: %v", cfg)
	}
	if _, ok := cfg["revocation_endpoint"].(string); !ok {
		t.Errorf("missing revocation_endpoint: %v", cfg)
	}
	if _, ok := cfg["introspection_endpoint"].(string); !ok {
		t.Errorf("missing introspection_endpoint: %v", cfg)
	}
}

func TestPKCE(t *testing.T) {
	h := testHandlers(t)
	verifier := base64.RawURLEncoding.EncodeToString([]byte("test-verifier-43-chars-long!!!!!!!!!!!!!!"))
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&state=s&username=test@example.com&password=password123&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	parsed, _ := url.Parse(resp.Header.Get("Location"))
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatal("missing code")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("client_id", "c")
	form.Set("code_verifier", verifier)
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	if tokResp.StatusCode != 200 {
		b, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("token status %d: %s", tokResp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&out)
	if _, ok := out["access_token"].(string); !ok {
		t.Errorf("missing access_token: %v", out)
	}
}

func TestPKCEInvalidVerifier(t *testing.T) {
	h := testHandlers(t)
	verifier := base64.RawURLEncoding.EncodeToString([]byte("test-verifier-43-chars-long!!!!!!!!!!!!!!"))
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&username=test@example.com&password=password123&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	parsed, _ := url.Parse(resp.Header.Get("Location"))
	code := parsed.Query().Get("code")
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("client_id", "c")
	form.Set("code_verifier", "wrong-verifier")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	if tokResp.StatusCode != 400 {
		t.Errorf("expected 400 for invalid verifier, got %d", tokResp.StatusCode)
	}
}

func TestTokenRevoke(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("scope", "offline_access")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	refreshTok := tokOut["refresh_token"].(string)
	revokeForm := url.Values{}
	revokeForm.Set("token", refreshTok)
	revokeForm.Set("token_type_hint", "refresh_token")
	revokeResp := h.doForm(t, "POST", "/oauth/revoke", revokeForm)
	if revokeResp.StatusCode != 200 {
		t.Errorf("revoke status %d, want 200", revokeResp.StatusCode)
	}
	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", refreshTok)
	reuseResp := h.doForm(t, "POST", "/oauth/token", form2)
	if reuseResp.StatusCode != 400 {
		t.Errorf("reuse of revoked token should fail with 400, got %d", reuseResp.StatusCode)
	}
}

func TestIntrospect(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	accessTok := tokOut["access_token"].(string)
	introForm := url.Values{}
	introForm.Set("token", accessTok)
	introResp := h.doForm(t, "POST", "/oauth/introspect", introForm)
	if introResp.StatusCode != 200 {
		t.Fatalf("introspect status %d", introResp.StatusCode)
	}
	var out map[string]interface{}
	json.NewDecoder(introResp.Body).Decode(&out)
	if active, ok := out["active"].(bool); !ok || !active {
		t.Errorf("expected active=true, got %v", out["active"])
	}
	if out["sub"] != "auth0|test-user" {
		t.Errorf("sub = %v", out["sub"])
	}
	introForm.Set("token", "invalid-token")
	badResp := h.doForm(t, "POST", "/oauth/introspect", introForm)
	var badOut map[string]interface{}
	json.NewDecoder(badResp.Body).Decode(&badOut)
	if badOut["active"] != false {
		t.Errorf("invalid token should have active=false, got %v", badOut["active"])
	}
}

func TestDeviceCodeFlow(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("client_id", "device-client")
	form.Set("scope", "openid")
	form.Set("audience", "https://api.example.com")
	resp := h.doForm(t, "POST", "/oauth/device/code", form)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("device code request status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	deviceCode := out["device_code"].(string)
	userCode := out["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("missing device_code or user_code: %v", out)
	}
	authForm := url.Values{}
	authForm.Set("user_code", userCode)
	authForm.Set("username", "test@example.com")
	authForm.Set("password", "password123")
	authForm.Set("action", "allow")
	authResp := h.doForm(t, "POST", "/oauth/device/authorize?user_code="+url.QueryEscape(userCode), authForm)
	if authResp.StatusCode != 200 {
		b, _ := io.ReadAll(authResp.Body)
		t.Fatalf("device authorize status %d: %s", authResp.StatusCode, b)
	}
	tokForm := url.Values{}
	tokForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokForm.Set("device_code", deviceCode)
	tokForm.Set("client_id", "device-client")
	tokResp := h.doForm(t, "POST", "/oauth/token", tokForm)
	if tokResp.StatusCode != 200 {
		b, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("device token status %d: %s", tokResp.StatusCode, b)
	}
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	if _, ok := tokOut["access_token"].(string); !ok {
		t.Errorf("missing access_token: %v", tokOut)
	}
}

func TestImplicitFlow(t *testing.T) {
	h := testHandlers(t)
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=token&client_id=c&redirect_uri=http://localhost/cb&state=s&username=test@example.com&password=password123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://localhost/cb") {
		t.Errorf("Location = %s", loc)
	}
	if !strings.Contains(loc, "#") {
		t.Error("implicit flow should return tokens in fragment")
	}
	parts := strings.SplitN(loc, "#", 2)
	frag := parts[1]
	if !strings.Contains(frag, "access_token=") {
		t.Errorf("fragment should contain access_token: %s", frag)
	}
	if !strings.Contains(frag, "state=s") {
		t.Errorf("fragment should contain state: %s", frag)
	}
}

func TestAudience(t *testing.T) {
	h := testHandlers(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "test@example.com")
	form.Set("password", "password123")
	form.Set("audience", "https://api.custom.com")
	resp := h.doForm(t, "POST", "/oauth/token", form)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	accessTok := out["access_token"].(string)
	parts := strings.Split(accessTok, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1] + "==")
	var claims map[string]interface{}
	json.Unmarshal(payload, &claims)
	if aud := claims["aud"]; aud != "https://api.custom.com" {
		t.Errorf("aud = %v, want https://api.custom.com", aud)
	}
}

func TestLogout(t *testing.T) {
	h := testHandlers(t)
	req := httptest.NewRequest("GET", "https://test.example.com/v2/logout?returnTo=http://localhost/cb&state=xyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "http://localhost/cb") || !strings.Contains(loc, "state=xyz") {
		t.Errorf("Location = %s", loc)
	}
}

func TestGetUserRoles(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/users/auth0|test-user/roles", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var roles []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&roles)
	if len(roles) < 1 {
		t.Errorf("expected at least 1 role, got %d", len(roles))
	}
}

func TestListRoles(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/roles", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var roles []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&roles)
	if len(roles) < 1 {
		t.Errorf("expected roles")
	}
}

func TestAuthorizePromptNone(t *testing.T) {
	h := testHandlers(t)
	req := httptest.NewRequest("GET", "https://test.example.com/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&prompt=none", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	parsed, _ := url.Parse(resp.Header.Get("Location"))
	if parsed.Query().Get("error") != "login_required" {
		t.Errorf("expected error=login_required, got %v", parsed.Query())
	}
}

func TestSignup(t *testing.T) {
	h := testHandlers(t)
	body := bytes.NewBufferString(`{"email":"new@example.com","password":"secret456"}`)
	resp := h.do(t, "POST", "/dbconnections/signup", body, "application/json")
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]string
	json.NewDecoder(resp.Body).Decode(&out)
	if out["email"] != "new@example.com" {
		t.Errorf("email = %v", out["email"])
	}
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "new@example.com")
	form.Set("password", "secret456")
	tokResp := h.doForm(t, "POST", "/oauth/token", form)
	if tokResp.StatusCode != 200 {
		b, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("login after signup status %d: %s", tokResp.StatusCode, b)
	}
}

// --- Management API tests ---

func TestListUsers(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/users", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var users []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		t.Fatal(err)
	}
	if len(users) < 1 {
		t.Errorf("expected at least 1 user, got %d", len(users))
	}
	if users[0]["email"] != "test@example.com" {
		t.Errorf("expected test@example.com, got %v", users[0]["email"])
	}
}

func TestListUsersWithTotals(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/users?include_totals=true&per_page=10", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["users"]; !ok {
		t.Errorf("expected users key in response")
	}
	if _, ok := out["total"]; !ok {
		t.Errorf("expected total key when include_totals=true")
	}
}

func TestListUsersSearch(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/users?q=test@example.com", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var users []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&users)
	if len(users) < 1 || users[0]["email"] != "test@example.com" {
		t.Errorf("search should find test@example.com: %v", users)
	}
}

func TestCreateUserMgmt(t *testing.T) {
	h := testHandlers(t)
	body := bytes.NewBufferString(`{"email":"mgmt@example.com","password":"pass123","name":"Mgmt User"}`)
	resp := h.do(t, "POST", "/api/v2/users", body, "application/json")
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if out["email"] != "mgmt@example.com" {
		t.Errorf("email = %v", out["email"])
	}
	if _, ok := out["user_id"]; !ok {
		t.Errorf("expected user_id in response")
	}
}

func TestGetUser(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/users/auth0|test-user", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if out["email"] != "test@example.com" {
		t.Errorf("email = %v", out["email"])
	}
	if out["user_id"] != "auth0|test-user" {
		t.Errorf("user_id = %v", out["user_id"])
	}
}

func TestGetUserNotFound(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/users/auth0|nonexistent", nil, "")
	if resp.StatusCode != 404 {
		t.Errorf("status %d, want 404", resp.StatusCode)
	}
}

func TestPatchUser(t *testing.T) {
	h := testHandlers(t)
	body := bytes.NewBufferString(`{"email":"updated@example.com","name":"Updated Name"}`)
	resp := h.do(t, "PATCH", "/api/v2/users/auth0|test-user", body, "application/json")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if out["email"] != "updated@example.com" {
		t.Errorf("email = %v", out["email"])
	}
	if out["name"] != "Updated Name" {
		t.Errorf("name = %v", out["name"])
	}
}

func TestDeleteUser(t *testing.T) {
	h := testHandlers(t)
	u := &store.User{ID: "auth0|to-delete", Email: "delete@example.com", DisplayName: "Delete Me", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := h.Store.CreateUser(context.Background(), u, "pass"); err != nil {
		t.Fatal(err)
	}
	resp := h.do(t, "DELETE", "/api/v2/users/auth0|to-delete", nil, "")
	if resp.StatusCode != 204 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	getResp := h.do(t, "GET", "/api/v2/users/auth0|to-delete", nil, "")
	if getResp.StatusCode != 404 {
		t.Errorf("user should be gone, status %d", getResp.StatusCode)
	}
}

func TestUserBlocks(t *testing.T) {
	h := testHandlers(t)
	userID := "auth0|test-user"
	resp := h.do(t, "GET", "/api/v2/users/"+userID+"/blocks", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET blocks status %d: %s", resp.StatusCode, b)
	}
	resp = h.do(t, "POST", "/api/v2/users/"+userID+"/blocks", nil, "")
	if resp.StatusCode != 204 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST block status %d: %s", resp.StatusCode, b)
	}
	resp = h.do(t, "GET", "/api/v2/users/"+userID+"/blocks", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("GET blocks after block status %d", resp.StatusCode)
	}
	var blocks []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&blocks)
	if len(blocks) == 0 {
		t.Error("expected blocked entry after POST block")
	}
	resp = h.do(t, "DELETE", "/api/v2/users/"+userID+"/blocks", nil, "")
	if resp.StatusCode != 204 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("DELETE block status %d: %s", resp.StatusCode, b)
	}
}

func TestCreateRole(t *testing.T) {
	h := testHandlers(t)
	body := bytes.NewBufferString(`{"name":"tester","description":"Test role"}`)
	resp := h.do(t, "POST", "/api/v2/roles", body, "application/json")
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if out["name"] != "tester" {
		t.Errorf("name = %v", out["name"])
	}
	if _, ok := out["id"]; !ok {
		t.Errorf("expected id in response")
	}
}

func TestGetRole(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/roles/rol_default", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if out["name"] != "user" {
		t.Errorf("name = %v (seed rol_default)", out["name"])
	}
}

func TestPatchRole(t *testing.T) {
	h := testHandlers(t)
	body := bytes.NewBufferString(`{"description":"Updated description"}`)
	resp := h.do(t, "PATCH", "/api/v2/roles/rol_admin", body, "application/json")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if out["description"] != "Updated description" {
		t.Errorf("description = %v", out["description"])
	}
}

func TestDeleteRole(t *testing.T) {
	h := testHandlers(t)
	body := bytes.NewBufferString(`{"name":"temp-role","description":"Temporary"}`)
	createResp := h.do(t, "POST", "/api/v2/roles", body, "application/json")
	if createResp.StatusCode != 201 {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create status %d: %s", createResp.StatusCode, b)
	}
	var created map[string]interface{}
	json.NewDecoder(createResp.Body).Decode(&created)
	roleID := created["id"].(string)
	delResp := h.do(t, "DELETE", "/api/v2/roles/"+roleID, nil, "")
	if delResp.StatusCode != 204 {
		b, _ := io.ReadAll(delResp.Body)
		t.Fatalf("delete status %d: %s", delResp.StatusCode, b)
	}
	getResp := h.do(t, "GET", "/api/v2/roles/"+roleID, nil, "")
	if getResp.StatusCode != 404 {
		t.Errorf("role should be gone, status %d", getResp.StatusCode)
	}
}

func TestListClients(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/clients", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var clients []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&clients)
	if len(clients) < 1 {
		t.Errorf("expected at least 1 client (seeded)")
	}
}

func TestGetClient(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/clients/radimal-e2e", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if out["client_id"] != "radimal-e2e" {
		t.Errorf("client_id = %v", out["client_id"])
	}
}

func TestPatchClient(t *testing.T) {
	h := testHandlers(t)
	body := bytes.NewBufferString(`{"name":"Updated Client Name","callbacks":["http://localhost/cb"]}`)
	resp := h.do(t, "PATCH", "/api/v2/clients/radimal-e2e", body, "application/json")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if out["name"] != "Updated Client Name" {
		t.Errorf("name = %v", out["name"])
	}
}

func TestListConnections(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/connections", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var conns []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&conns)
	if len(conns) < 1 {
		t.Errorf("expected at least 1 connection (seeded)")
	}
}

func TestGetConnection(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/connections/con_db_main", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	if out["name"] != "Username-Password-Authentication" {
		t.Errorf("name = %v", out["name"])
	}
}

func TestListLogs(t *testing.T) {
	h := testHandlers(t)
	resp := h.do(t, "GET", "/api/v2/logs", nil, "")
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var logs []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&logs)
}
