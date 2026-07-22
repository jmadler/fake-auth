//go:build integration
// +build integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmadler/auth2/internal/acl"
	"github.com/jmadler/auth2/internal/graphql"
	"github.com/jmadler/auth2/internal/grants"
	"github.com/jmadler/auth2/internal/handlers"
	"github.com/jmadler/auth2/internal/scim"
	"github.com/jmadler/auth2/internal/sessions"
	"github.com/jmadler/auth2/internal/store"
	"github.com/jmadler/auth2/internal/token"
)

func setupIntegrationServer(t *testing.T) (baseURL string, cleanup func()) {
	return setupIntegrationServerWithSession(t, false)
}

func setupIntegrationServerWithSession(t *testing.T, useSession bool) (baseURL string, cleanup func()) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "auth0.db")
	st, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	u := &store.User{
		ID:             "auth0|int-user",
		Email:          "integration@example.com",
		DisplayName:    "Integration User",
		OrganizationID: 1,
		EnterpriseID:   1,
		Role:           "user",
	}
	if err := st.CreateUser(context.Background(), u, "pass123"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	issuer, err := token.NewIssuer("http://localhost:0/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	grantStore := grants.NewStore(5*time.Minute, 24*time.Hour)
	h := &handlers.Handlers{
		Store:      st,
		Issuer:     issuer,
		IssuerURL:  "http://localhost:0",
		GrantStore: grantStore,
	}
	if useSession {
		h.SessionStore = sessions.NewStore(7 * 24 * time.Hour)
	}
	issuerURL := "http://localhost:0"
	scimHandler := scim.AuthMiddleware(scim.NewHandler(st, issuerURL))
	mux := http.NewServeMux()
	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scimHandler))
	mux.Handle("/", h)
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	time.Sleep(50 * time.Millisecond)
	baseURL = "http://" + listener.Addr().String()
	cleanup = func() {
		srv.Shutdown(context.Background())
		st.Close()
	}
	return baseURL, cleanup
}

func setupIntegrationServerWithACL(t *testing.T, rules []acl.Rule) (baseURL string, cleanup func()) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "auth0.db")
	st, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	u := &store.User{
		ID:             "auth0|int-user",
		Email:          "integration@example.com",
		DisplayName:    "Integration User",
		OrganizationID: 1,
		EnterpriseID:   1,
		Role:           "user",
	}
	if err := st.CreateUser(context.Background(), u, "pass123"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	issuer, err := token.NewIssuer("http://localhost:0/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	grantStore := grants.NewStore(5*time.Minute, 24*time.Hour)
	h := &handlers.Handlers{
		Store:      st,
		Issuer:     issuer,
		IssuerURL:  "http://localhost:0",
		GrantStore: grantStore,
	}
	aclMiddleware := acl.Middleware(acl.New(rules))
	handler := aclMiddleware(h)
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(listener)
	time.Sleep(50 * time.Millisecond)
	baseURL = "http://" + listener.Addr().String()
	cleanup = func() {
		srv.Shutdown(context.Background())
		st.Close()
	}
	return baseURL, cleanup
}


func TestIntegrationHealth(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("GET /health status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "ok") {
		t.Errorf("GET /health body %q does not contain 'ok'", body)
	}
}

func TestIntegrationLive(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	resp, err := http.Get(baseURL + "/live")
	if err != nil {
		t.Fatalf("GET /live: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("GET /live status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "ok") {
		t.Errorf("GET /live body %q does not contain 'ok'", body)
	}
}

func TestIntegrationReady(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	resp, err := http.Get(baseURL + "/ready")
	if err != nil {
		t.Fatalf("GET /ready: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("GET /ready status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "ok") {
		t.Errorf("GET /ready body %q does not contain 'ok'", body)
	}
}

func TestIntegrationACL_Deny(t *testing.T) {
	rules := []acl.Rule{
		{Action: "deny", Path: "/oauth/token"},
	}
	baseURL, cleanup := setupIntegrationServerWithACL(t, rules)
	defer cleanup()

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "integration@example.com")
	form.Set("password", "pass123")
	form.Set("client_id", "test-client")
	resp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("ACL should deny /oauth/token with 403, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "access_denied") {
		t.Errorf("body should contain access_denied, got %s", body)
	}
}

func TestIntegrationACL_AllowOtherPaths(t *testing.T) {
	rules := []acl.Rule{
		{Action: "deny", Path: "/admin"},
	}
	baseURL, cleanup := setupIntegrationServerWithACL(t, rules)
	defer cleanup()

	// /oauth/token should still work (no matching rule = allow)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "integration@example.com")
	form.Set("password", "pass123")
	form.Set("client_id", "test-client")
	resp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("ACL should allow /oauth/token, got %d", resp.StatusCode)
	}
}

func TestIntegrationLoginCustomTemplate(t *testing.T) {
	tpl := `<!DOCTYPE html><html><body><h1>Custom Login</h1>
<form method="post" action="/login">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="scope" value="{{.Scope}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="response_type" value="{{.ResponseType}}">
<input type="hidden" name="nonce" value="{{.Nonce}}">
<input type="hidden" name="audience" value="{{.Audience}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
<input type="text" name="username" value="{{.LoginHint}}">
<input type="password" name="password">
<button type="submit">Sign in</button></form></body></html>`
	dir := t.TempDir()
	tplPath := filepath.Join(dir, "login_custom.html")
	if err := os.WriteFile(tplPath, []byte(tpl), 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	os.Setenv("LOGIN_PAGE_TEMPLATE", tplPath)
	defer os.Unsetenv("LOGIN_PAGE_TEMPLATE")

	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()

	resp, err := http.Get(baseURL + "/login?client_id=custom-client&redirect_uri=http://localhost/cb&scope=openid&state=st1&response_type=code&login_hint=user@example.com")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Custom Login") {
		t.Errorf("body should contain custom template title, got %s", body)
	}
	if !strings.Contains(string(body), "custom-client") {
		t.Errorf("body should contain client_id, got %s", body)
	}
}

func TestIntegrationGraphQL(t *testing.T) {
	os.Setenv("GRAPHQL_TEST_API_ENABLED", "true")
	os.Setenv("ADMIN_API_KEY", "integration-admin-key")
	defer func() {
		os.Unsetenv("GRAPHQL_TEST_API_ENABLED")
		os.Unsetenv("ADMIN_API_KEY")
	}()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "auth0.db")
	st, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	issuer, err := token.NewIssuer("http://localhost:0/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	grantStore := grants.NewStore(5*time.Minute, 24*time.Hour)
	h := &handlers.Handlers{
		Store:      st,
		Issuer:     issuer,
		IssuerURL:  "http://localhost:0",
		GrantStore: grantStore,
	}
	mux := http.NewServeMux()
	mux.Handle("/graphql", graphql.Handler(st))
	mux.Handle("/", h)
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	time.Sleep(50 * time.Millisecond)
	baseURL := "http://" + listener.Addr().String()
	defer func() {
		srv.Shutdown(context.Background())
		st.Close()
	}()

	reqBody := `{"query":"mutation { createUser(email: \"gql-int@example.com\", password: \"SecurePass123!\", name: \"GQL Integration\") { id email name } }"}`
	req, _ := http.NewRequest("POST", baseURL+"/graphql", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer integration-admin-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("graphql status %d: %s", resp.StatusCode, b)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("empty graphql response")
	}
	if errs, ok := result["errors"]; ok && errs != nil {
		t.Errorf("graphql errors: %v", errs)
	}
	data, _ := result["data"].(map[string]interface{})
	createUser, _ := data["createUser"].(map[string]interface{})
	if createUser["email"] != "gql-int@example.com" {
		t.Errorf("email = %v", createUser["email"])
	}
}

func TestIntegrationMetrics(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("GET /metrics status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "auth2") && !strings.Contains(string(body), "authorize") {
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200]
		}
		t.Errorf("metrics body should contain 'auth2' or 'authorize', got %q", preview)
	}
}

func TestIntegrationRevoke(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "integration@example.com")
	form.Set("password", "pass123")
	form.Set("client_id", "test-client")
	form.Set("scope", "openid offline_access")
	tokResp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	tokResp.Body.Close()
	refreshTok, ok := tokOut["refresh_token"].(string)
	if !ok {
		t.Fatal("missing refresh_token")
	}
	revForm := url.Values{}
	revForm.Set("token", refreshTok)
	revForm.Set("token_type_hint", "refresh_token")
	revResp, err := http.Post(baseURL+"/oauth/revoke", "application/x-www-form-urlencoded", strings.NewReader(revForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	revResp.Body.Close()
	if revResp.StatusCode != 200 {
		t.Errorf("revoke status %d", revResp.StatusCode)
	}
	reuseForm := url.Values{}
	reuseForm.Set("grant_type", "refresh_token")
	reuseForm.Set("refresh_token", refreshTok)
	reuseResp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(reuseForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	reuseResp.Body.Close()
	if reuseResp.StatusCode != 400 {
		t.Errorf("reusing revoked token should fail with 400, got %d", reuseResp.StatusCode)
	}
}

func TestIntegrationIntrospect(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "integration@example.com")
	form.Set("password", "pass123")
	form.Set("client_id", "test-client")
	tokResp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	tokResp.Body.Close()
	accessTok := tokOut["access_token"].(string)
	introForm := url.Values{}
	introForm.Set("token", accessTok)
	introResp, err := http.Post(baseURL+"/oauth/introspect", "application/x-www-form-urlencoded", strings.NewReader(introForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer introResp.Body.Close()
	if introResp.StatusCode != 200 {
		t.Errorf("introspect status %d", introResp.StatusCode)
	}
	var introOut map[string]interface{}
	json.NewDecoder(introResp.Body).Decode(&introOut)
	if active, ok := introOut["active"].(bool); !ok || !active {
		t.Errorf("valid token should have active:true, got %v", introOut)
	}
	badForm := url.Values{}
	badForm.Set("token", "invalid-token")
	badIntroResp, err := http.Post(baseURL+"/oauth/introspect", "application/x-www-form-urlencoded", strings.NewReader(badForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer badIntroResp.Body.Close()
	var badOut map[string]interface{}
	json.NewDecoder(badIntroResp.Body).Decode(&badOut)
	if active, ok := badOut["active"].(bool); !ok || active {
		t.Errorf("invalid token should have active:false, got %v", badOut)
	}
}

func TestIntegrationDeviceCodeFlow(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	dcForm := url.Values{}
	dcForm.Set("client_id", "test-client")
	dcResp, err := http.Post(baseURL+"/oauth/device/code", "application/x-www-form-urlencoded", strings.NewReader(dcForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	var dcOut map[string]interface{}
	json.NewDecoder(dcResp.Body).Decode(&dcOut)
	dcResp.Body.Close()
	deviceCode := dcOut["device_code"].(string)
	userCode := dcOut["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("missing device_code or user_code: %v", dcOut)
	}
	authForm := url.Values{}
	authForm.Set("user_code", userCode)
	authForm.Set("username", "integration@example.com")
	authForm.Set("password", "pass123")
	authResp, err := http.Post(baseURL+"/oauth/device/authorize?user_code="+url.QueryEscape(userCode), "application/x-www-form-urlencoded", strings.NewReader(authForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != 200 {
		t.Errorf("device authorize status %d", authResp.StatusCode)
	}
	tokForm := url.Values{}
	tokForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokForm.Set("device_code", deviceCode)
	tokForm.Set("client_id", "test-client")
	tokResp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(tokForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer tokResp.Body.Close()
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

func TestIntegrationPKCEFlow(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	authURL := baseURL + "/authorize?response_type=code&client_id=ac-client&redirect_uri=http://localhost:9999/cb&scope=openid&state=s1&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256&username=integration@example.com&password=pass123"
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	parsed, _ := url.Parse(loc)
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatal("missing code in redirect")
	}
	tokForm := url.Values{}
	tokForm.Set("grant_type", "authorization_code")
	tokForm.Set("code", code)
	tokForm.Set("redirect_uri", "http://localhost:9999/cb")
	tokForm.Set("client_id", "ac-client")
	tokForm.Set("code_verifier", verifier)
	tokResp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(tokForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != 200 {
		b, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("token status %d: %s", tokResp.StatusCode, b)
	}
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	if _, ok := tokOut["access_token"].(string); !ok {
		t.Errorf("missing access_token: %v", tokOut)
	}
}

func TestIntegrationImplicitFlow(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	authURL := baseURL + "/authorize?response_type=token&client_id=impl-client&redirect_uri=http://localhost:9999/cb&scope=openid&state=s1&username=integration@example.com&password=pass123"
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "#") {
		t.Fatal("implicit flow should redirect with fragment")
	}
	parts := strings.SplitN(loc, "#", 2)
	frag, _ := url.ParseQuery(parts[1])
	accessToken := frag.Get("access_token")
	if accessToken == "" {
		t.Errorf("missing access_token in fragment: %s", loc)
	}
}

func TestIntegrationSessionFlow(t *testing.T) {
	baseURL, cleanup := setupIntegrationServerWithSession(t, true)
	defer cleanup()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	loginForm := url.Values{}
	loginForm.Set("client_id", "ac-client")
	loginForm.Set("redirect_uri", "http://localhost:9999/cb1")
	loginForm.Set("scope", "openid")
	loginForm.Set("state", "s1")
	loginForm.Set("username", "integration@example.com")
	loginForm.Set("password", "pass123")
	loginReq, _ := http.NewRequest("POST", baseURL+"/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != 302 {
		t.Errorf("login status %d", loginResp.StatusCode)
	}
	if loginResp.Header.Get("Set-Cookie") == "" {
		t.Error("expected Set-Cookie from login")
	}
	authURL := baseURL + "/authorize?response_type=code&client_id=ac-client&redirect_uri=http://localhost:9999/cb2&scope=openid&state=s2"
	authResp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != 302 {
		t.Fatalf("authorize with cookie: status %d", authResp.StatusCode)
	}
	loc := authResp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://localhost:9999/cb2") {
		t.Errorf("Location = %s", loc)
	}
	parsed, _ := url.Parse(loc)
	if parsed.Query().Get("code") == "" {
		t.Error("missing code in redirect (session should have provided auth)")
	}
}

func TestIntegrationManagementAPI(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "integration@example.com")
	form.Set("password", "pass123")
	form.Set("client_id", "test-client")
	tokResp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	var tokOut map[string]interface{}
	json.NewDecoder(tokResp.Body).Decode(&tokOut)
	tokResp.Body.Close()
	accessTok, _ := tokOut["access_token"].(string)
	bearer := "Bearer " + accessTok
	get := func(path string) (*http.Response, error) {
		req, _ := http.NewRequest("GET", baseURL+path, nil)
		req.Header.Set("Authorization", bearer)
		return http.DefaultClient.Do(req)
	}
	post := func(path, contentType string, body io.Reader) (*http.Response, error) {
		req, _ := http.NewRequest("POST", baseURL+path, body)
		req.Header.Set("Authorization", bearer)
		req.Header.Set("Content-Type", contentType)
		return http.DefaultClient.Do(req)
	}
	patch := func(path string, body io.Reader) (*http.Response, error) {
		req, _ := http.NewRequest("PATCH", baseURL+path, body)
		req.Header.Set("Authorization", bearer)
		req.Header.Set("Content-Type", "application/json")
		return http.DefaultClient.Do(req)
	}
	del := func(path string) (*http.Response, error) {
		req, _ := http.NewRequest("DELETE", baseURL+path, nil)
		req.Header.Set("Authorization", bearer)
		return http.DefaultClient.Do(req)
	}
	resp, err := get("/api/v2/users")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("GET /api/v2/users: %d", resp.StatusCode)
	}
	createBody := `{"email":"mgmt@test.com","password":"mgmtpass","connection":"Username-Password-Authentication"}`
	createResp, err := post("/api/v2/users", "application/json", strings.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}
	var created map[string]interface{}
	json.NewDecoder(createResp.Body).Decode(&created)
	createResp.Body.Close()
	if createResp.StatusCode != 201 {
		t.Errorf("POST /api/v2/users: %d", createResp.StatusCode)
	}
	userID, _ := created["user_id"].(string)
	if userID == "" {
		userID, _ = created["id"].(string)
	}
	if userID == "" {
		t.Fatal("no user_id in create response")
	}
	getUserResp, err := get("/api/v2/users/" + url.PathEscape(userID))
	if err != nil {
		t.Fatal(err)
	}
	getUserResp.Body.Close()
	if getUserResp.StatusCode != 200 {
		t.Errorf("GET /api/v2/users/{id}: %d", getUserResp.StatusCode)
	}
	patchBody := `{"user_metadata":{"foo":"bar"}}`
	patchResp, err := patch("/api/v2/users/"+url.PathEscape(userID), strings.NewReader(patchBody))
	if err != nil {
		t.Fatal(err)
	}
	patchResp.Body.Close()
	if patchResp.StatusCode != 200 {
		t.Errorf("PATCH /api/v2/users/{id}: %d", patchResp.StatusCode)
	}
	rolesResp, err := get("/api/v2/roles")
	if err != nil {
		t.Fatal(err)
	}
	rolesResp.Body.Close()
	if rolesResp.StatusCode != 200 {
		t.Errorf("GET /api/v2/roles: %d", rolesResp.StatusCode)
	}
	clientsResp, err := get("/api/v2/clients")
	if err != nil {
		t.Fatal(err)
	}
	clientsResp.Body.Close()
	if clientsResp.StatusCode != 200 {
		t.Errorf("GET /api/v2/clients: %d", clientsResp.StatusCode)
	}
	connResp, err := get("/api/v2/connections")
	if err != nil {
		t.Fatal(err)
	}
	connResp.Body.Close()
	if connResp.StatusCode != 200 {
		t.Errorf("GET /api/v2/connections: %d", connResp.StatusCode)
	}
	logsResp, err := get("/api/v2/logs")
	if err != nil {
		t.Fatal(err)
	}
	logsResp.Body.Close()
	if logsResp.StatusCode != 200 {
		t.Errorf("GET /api/v2/logs: %d", logsResp.StatusCode)
	}
	getBlocksResp, err := get("/api/v2/users/" + url.PathEscape(userID) + "/blocks")
	if err != nil {
		t.Fatal(err)
	}
	getBlocksResp.Body.Close()
	if getBlocksResp.StatusCode != 200 {
		t.Errorf("GET /api/v2/users/{id}/blocks: %d", getBlocksResp.StatusCode)
	}
	postBlocksResp, err := post("/api/v2/users/"+url.PathEscape(userID)+"/blocks", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	postBlocksResp.Body.Close()
	if postBlocksResp.StatusCode != 204 && postBlocksResp.StatusCode != 200 {
		t.Errorf("POST /api/v2/users/{id}/blocks: %d", postBlocksResp.StatusCode)
	}
	delBlocksResp, err := del("/api/v2/users/" + url.PathEscape(userID) + "/blocks")
	if err != nil {
		t.Fatal(err)
	}
	delBlocksResp.Body.Close()
	if delBlocksResp.StatusCode != 204 && delBlocksResp.StatusCode != 200 {
		t.Errorf("DELETE /api/v2/users/{id}/blocks: %d", delBlocksResp.StatusCode)
	}
	delResp, err := del("/api/v2/users/" + url.PathEscape(userID))
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != 204 {
		t.Errorf("DELETE /api/v2/users/{id}: %d", delResp.StatusCode)
	}
}

func TestIntegrationOAuthFlows(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()

	t.Run("password_grant", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("username", "integration@example.com")
		form.Set("password", "pass123")
		form.Set("client_id", "test-client")
		resp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status %d: %s", resp.StatusCode, b)
		}
		var out map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&out)
		if _, ok := out["access_token"].(string); !ok {
			t.Errorf("missing access_token: %v", out)
		}
	})

	t.Run("authorization_code_flow", func(t *testing.T) {
		authURL := baseURL + "/authorize?response_type=code&client_id=ac-client&redirect_uri=http://localhost:9999/cb&scope=openid%20offline_access&state=s1&username=integration@example.com&password=pass123"
		client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Get(authURL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 302 {
			t.Fatalf("status %d, want 302", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, "http://localhost:9999/cb") {
			t.Errorf("Location = %s", loc)
		}
		parsed, _ := url.Parse(loc)
		code := parsed.Query().Get("code")
		if code == "" {
			t.Fatal("missing code in redirect")
		}
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", "http://localhost:9999/cb")
		form.Set("client_id", "ac-client")
		tokResp, err := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		defer tokResp.Body.Close()
		if tokResp.StatusCode != 200 {
			b, _ := io.ReadAll(tokResp.Body)
			t.Fatalf("token status %d: %s", tokResp.StatusCode, b)
		}
		var tokOut map[string]interface{}
		json.NewDecoder(tokResp.Body).Decode(&tokOut)
		if _, ok := tokOut["access_token"].(string); !ok {
			t.Errorf("missing access_token: %v", tokOut)
		}
		if _, ok := tokOut["refresh_token"].(string); !ok {
			t.Errorf("expected refresh_token: %v", tokOut)
		}
	})

	t.Run("userinfo_with_token", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("username", "integration@example.com")
		form.Set("password", "pass123")
		tokResp, _ := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		var tokOut map[string]interface{}
		json.NewDecoder(tokResp.Body).Decode(&tokOut)
		tokResp.Body.Close()
		accessTok := tokOut["access_token"].(string)

		req, _ := http.NewRequest("GET", baseURL+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+accessTok)
		uiResp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer uiResp.Body.Close()
		if uiResp.StatusCode != 200 {
			b, _ := io.ReadAll(uiResp.Body)
			t.Fatalf("userinfo status %d: %s", uiResp.StatusCode, b)
		}
		var user map[string]interface{}
		json.NewDecoder(uiResp.Body).Decode(&user)
		if user["email"] != "integration@example.com" {
			t.Errorf("email = %v", user["email"])
		}
	})

	t.Run("refresh_token_rotation", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("username", "integration@example.com")
		form.Set("password", "pass123")
		form.Set("scope", "openid offline_access")
		tokResp, _ := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		var tokOut map[string]interface{}
		json.NewDecoder(tokResp.Body).Decode(&tokOut)
		tokResp.Body.Close()
		rt1 := tokOut["refresh_token"].(string)

		form2 := url.Values{}
		form2.Set("grant_type", "refresh_token")
		form2.Set("refresh_token", rt1)
		refreshResp, _ := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form2.Encode()))
		var refreshOut map[string]interface{}
		json.NewDecoder(refreshResp.Body).Decode(&refreshOut)
		refreshResp.Body.Close()
		rt2 := refreshOut["refresh_token"].(string)
		if rt1 == rt2 {
			t.Error("expected new refresh token (rotation)")
		}
		form2.Set("refresh_token", rt1)
		reuseResp, _ := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form2.Encode()))
		if reuseResp.StatusCode != 400 {
			t.Errorf("reusing old refresh token should fail: %d", reuseResp.StatusCode)
		}
	})

	t.Run("signup_and_login", func(t *testing.T) {
		body := bytes.NewBufferString(`{"email":"newuser@test.com","password":"NewPass9"}`)
		signupResp, err := http.Post(baseURL+"/dbconnections/signup", "application/json", body)
		if err != nil {
			t.Fatal(err)
		}
		signupResp.Body.Close()
		if signupResp.StatusCode != 201 {
			t.Fatalf("signup status %d", signupResp.StatusCode)
		}
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("username", "newuser@test.com")
		form.Set("password", "NewPass9")
		loginResp, _ := http.Post(baseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if loginResp.StatusCode != 200 {
			b, _ := io.ReadAll(loginResp.Body)
			t.Fatalf("login status %d: %s", loginResp.StatusCode, b)
		}
	})

	t.Run("jwks_and_oidc_config", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("oidc config status %d", resp.StatusCode)
		}
		var cfg map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
			t.Fatal(err)
		}
		if _, ok := cfg["userinfo_endpoint"]; !ok {
			t.Error("missing userinfo_endpoint")
		}
		jwksResp, err := http.Get(baseURL + "/.well-known/jwks.json")
		if err != nil {
			t.Fatal(err)
		}
		defer jwksResp.Body.Close()
		if jwksResp.StatusCode != 200 {
			t.Fatalf("jwks status %d", jwksResp.StatusCode)
		}
	})
}

func TestIntegrationSCIM(t *testing.T) {
	os.Setenv("PASSWORD_POLICY_MIN_LENGTH", "6")
	defer os.Unsetenv("PASSWORD_POLICY_MIN_LENGTH")

	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()

	// SCIM list users (no auth when SCIM_API_TOKEN not set)
	resp, err := http.Get(baseURL + "/scim/v2/Users")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /scim/v2/Users: %d %s", resp.StatusCode, b)
	}
	var list struct {
		TotalResults int `json:"totalResults"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if list.TotalResults < 1 {
		t.Errorf("expected at least 1 user (seed), got %d", list.TotalResults)
	}

	// SCIM create user
	createBody := `{"userName":"scim-user@example.com","name":{"givenName":"Scim","familyName":"User"},"password":"ChangeMe123!"}`
	createResp, err := http.Post(baseURL+"/scim/v2/Users", "application/scim+json", strings.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != 201 {
		b, _ := io.ReadAll(createResp.Body)
		t.Fatalf("POST /scim/v2/Users: %d %s", createResp.StatusCode, b)
	}
	var created struct {
		ID       string `json:"id"`
		UserName string `json:"userName"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.UserName != "scim-user@example.com" {
		t.Errorf("userName = %q", created.UserName)
	}

	// SCIM get user
	getResp, err := http.Get(baseURL + "/scim/v2/Users/" + created.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != 200 {
		t.Fatalf("GET /scim/v2/Users/{id}: %d", getResp.StatusCode)
	}
}

func TestIntegrationOrganizations(t *testing.T) {
	baseURL, cleanup := setupIntegrationServer(t)
	defer cleanup()

	// Create organization (no admin auth in dev mode)
	body := `{"name":"Test Org","display_name":"Test Organization"}`
	resp, err := http.Post(baseURL+"/api/v2/organizations", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /api/v2/organizations: %d %s", resp.StatusCode, b)
	}
	var org struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if org.Name != "Test Org" {
		t.Errorf("name = %q", org.Name)
	}

	// List organizations (returns array)
	listResp, err := http.Get(baseURL + "/api/v2/organizations")
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != 200 {
		t.Fatalf("GET /api/v2/organizations: %d", listResp.StatusCode)
	}
	var list []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) < 1 {
		t.Error("expected at least 1 organization")
	}

	// Add member
	memberBody := `{"user_id":"auth0|int-user","role":"member"}`
	memberResp, err := http.Post(baseURL+"/api/v2/organizations/"+org.ID+"/members", "application/json", strings.NewReader(memberBody))
	if err != nil {
		t.Fatal(err)
	}
	defer memberResp.Body.Close()
	if memberResp.StatusCode != 201 && memberResp.StatusCode != 200 {
		b, _ := io.ReadAll(memberResp.Body)
		t.Fatalf("POST members: %d %s", memberResp.StatusCode, b)
	}
}
