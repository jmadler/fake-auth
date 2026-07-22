package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"html"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/jmadler/auth2/internal/audit"
	"github.com/jmadler/auth2/internal/clients"
	"github.com/jmadler/auth2/internal/fapi"
	"github.com/jmadler/auth2/internal/enterprise"
	"github.com/jmadler/auth2/internal/email"
	"github.com/jmadler/auth2/internal/grants"
	"github.com/jmadler/auth2/internal/metrics"
	"github.com/jmadler/auth2/internal/password"
	"github.com/jmadler/auth2/internal/pkce"
	"github.com/jmadler/auth2/internal/rules"
	"github.com/jmadler/auth2/internal/sessions"
	"github.com/jmadler/auth2/internal/sms"
	"github.com/jmadler/auth2/internal/social"
	"github.com/jmadler/auth2/internal/store"
	"github.com/jmadler/auth2/internal/token"
	"github.com/jmadler/auth2/internal/tokenvault"
)

const sessionCookieName = "auth2_session"
const sessionCookieMaxAge = 86400 * 7 // 7 days

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

type Handlers struct {
	Store               store.Store
	Issuer              *token.Issuer
	IssuerURL           string
	GrantStore          grants.GrantStore  // nil = no grant storage
	RulesRunner         *rules.Runner
	ClientRegistry      *clients.Registry  // nil = no client validation
	SessionStore        sessions.Store    // nil = no server-side sessions
	RedisClient         *redis.Client     // optional, for health check when Redis is used
	AccessTokenLifetime int               // seconds, 0 = default 86400
	IDTokenLifetime     int               // seconds, 0 = default 86400
	MFAEnabled          bool              // MFA_ENABLED env; enables MFA endpoints and password-grant challenge
	AdaptiveMFAEnabled  bool              // ADAPTIVE_MFA_ENABLED; only require MFA when risky (new IP, no session)
	WebAuthnHandler     http.Handler     // optional; handles /webauthn/* when set
	SAMLConfig          *SAMLConfig      // optional; for SAML IdP (entity_id, cert, key)
	AdminAPIKey         string           // optional; for token vault admin access
}

func (h *Handlers) accessTokenLifetime() int {
	if h.AccessTokenLifetime > 0 {
		return h.AccessTokenLifetime
	}
	return 86400
}

func (h *Handlers) idTokenLifetime() int {
	if h.IDTokenLifetime > 0 {
		return h.IDTokenLifetime
	}
	return 86400
}

func (h *Handlers) issuerURL() string {
	if h.IssuerURL != "" {
		return strings.TrimSuffix(h.IssuerURL, "/")
	}
	return "https://auth2.example.com"
}

func setRateLimitHeaders(w http.ResponseWriter) {
	w.Header().Set("x-ratelimit-limit", "1000")
	w.Header().Set("x-ratelimit-remaining", "999")
	w.Header().Set("x-ratelimit-reset", "9999999999")
}

func (h *Handlers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && path == "/health":
		h.handleHealth(w, r)
	case r.Method == http.MethodGet && path == "/live":
		h.handleLive(w)
	case r.Method == http.MethodGet && path == "/ready":
		h.handleReady(w, r)
	case r.Method == http.MethodGet && path == "/metrics":
		h.handleMetrics(w, r)
	case r.Method == http.MethodGet && path == "/authorize":
		h.handleAuthorize(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && path == "/login":
		h.handleLogin(w, r)
	case r.Method == http.MethodPost && path == "/oauth/token":
		h.handleToken(w, r)
	case r.Method == http.MethodPost && path == "/oauth/revoke":
		h.handleRevoke(w, r)
	case r.Method == http.MethodPost && path == "/oauth/introspect":
		h.handleIntrospect(w, r)
	case r.Method == http.MethodPost && path == "/oauth/device/code":
		h.handleDeviceCodeRequest(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && path == "/oauth/device/authorize":
		h.handleDeviceAuthorize(w, r)
	case r.Method == http.MethodPost && path == "/oauth/ciba/request":
		h.handleCIBARequest(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && path == "/ciba/verify":
		h.handleCIBAVerify(w, r)
	case r.Method == http.MethodGet && path == "/userinfo":
		h.handleUserinfo(w, r)
	case r.Method == http.MethodPost && path == "/tokeninfo":
		h.handleTokeninfo(w, r)
	case r.Method == http.MethodPost && path == "/dbconnections/signup":
		h.handleSignup(w, r)
	case r.Method == http.MethodPost && path == "/dbconnections/change_password":
		h.handleChangePassword(w, r)
	case r.Method == http.MethodPost && path == "/passwordless/start":
		h.handlePasswordlessStart(w, r)
	case r.Method == http.MethodPost && path == "/passwordless/reset":
		h.handlePasswordReset(w, r)
	case r.Method == http.MethodGet && path == "/passwordless/verify":
		h.handlePasswordlessVerify(w, r)
	case r.Method == http.MethodPost && path == "/passwordless/confirm":
		h.handlePasswordResetConfirm(w, r)
	case r.Method == http.MethodPost && path == "/mfa/enroll":
		h.handleMFAEnroll(w, r)
	case r.Method == http.MethodPost && path == "/mfa/verify":
		h.handleMFAVerify(w, r)
	case r.Method == http.MethodPost && path == "/mfa/challenge":
		h.handleMFAChallenge(w, r)
	case h.WebAuthnHandler != nil && strings.HasPrefix(path, "/webauthn/"):
		h.WebAuthnHandler.ServeHTTP(w, r)
	case r.Method == http.MethodGet && path == "/api/v2/users":
		h.handleListUsers(w, r)
	case r.Method == http.MethodGet && path == "/api/v2/users/export":
		h.handleUsersExport(w, r)
	case r.Method == http.MethodPost && path == "/api/v2/users/import":
		h.handleUsersImport(w, r)
	case r.Method == http.MethodPost && path == "/api/v2/users":
		h.handleCreateUserMgmt(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/users/") && strings.HasSuffix(path, "/blocks"):
		h.handleGetUserBlocks(w, r, path)
	case (r.Method == http.MethodPost || r.Method == http.MethodDelete) && strings.HasPrefix(path, "/api/v2/users/") && strings.HasSuffix(path, "/blocks"):
		h.handleUserBlocksModify(w, r, path)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/users/") && strings.HasSuffix(path, "/export"):
		h.handleUserGDPRExport(w, r, path)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/users/") && !strings.Contains(path, "/roles") && !strings.Contains(path, "/permissions") && !strings.Contains(path, "/blocks"):
		h.handleGetUser(w, r, path)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/v2/users/") && !strings.Contains(path, "/roles") && !strings.Contains(path, "/permissions") && !strings.Contains(path, "/blocks"):
		h.handleDeleteUser(w, r, path)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v2/users/") && !strings.Contains(path, "/roles"):
		h.handlePatchUser(w, r)
	case (r.Method == http.MethodDelete || r.Method == http.MethodPost) && strings.Contains(path, "/api/v2/users/") && strings.HasSuffix(path, "/roles") && r.Method != http.MethodGet:
		h.handleUserRolesModify(w, r, path)
	case r.Method == http.MethodGet && path == "/.well-known/jwks.json":
		h.handleJWKS(w)
	case r.Method == http.MethodGet && path == "/.well-known/openid-configuration":
		h.handleOpenIDConfig(w)
	case r.Method == http.MethodGet && path == "/v2/logout":
		h.handleLogout(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && (path == "/u/login" || path == "/usernamepassword/login"):
		h.handleUniversalLogin(w, r)
	case r.Method == http.MethodGet && path == "/login/callback":
		h.handleLoginCallback(w, r)
	case r.Method == http.MethodGet && path == "/callback/social":
		h.handleSocialCallback(w, r)
	case r.Method == http.MethodGet && path == "/callback/enterprise":
		h.handleEnterpriseCallback(w, r)
	case r.Method == http.MethodGet && path == "/.well-known/saml-metadata":
		h.handleSAMLMetadata(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && path == "/saml/sso":
		h.handleSAMLSSO(w, r)
	case r.Method == http.MethodPost && path == "/api/v2/saml/sp":
		h.handleCreateSAMLSP(w, r)
	case r.Method == http.MethodGet && path == "/login/enterprise":
		h.handleLoginEnterprise(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/users/") && strings.HasSuffix(path, "/roles"):
		h.handleGetUserRoles(w, r, path)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/users/") && strings.HasSuffix(path, "/permissions"):
		h.handleGetUserPermissions(w, r, path)
	case r.Method == http.MethodGet && path == "/api/v2/roles":
		h.handleListRoles(w, r)
	case r.Method == http.MethodPost && path == "/api/v2/roles":
		h.handleCreateRole(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/roles/"):
		h.handleGetRole(w, r, path)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v2/roles/"):
		h.handlePatchRole(w, r, path)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/v2/roles/"):
		h.handleDeleteRole(w, r, path)
	case r.Method == http.MethodGet && path == "/api/v2/clients":
		h.handleListClients(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/clients/"):
		h.handleGetClient(w, r, path)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v2/clients/"):
		h.handlePatchClient(w, r, path)
	case r.Method == http.MethodGet && path == "/api/v2/connections":
		h.handleListConnections(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/connections/"):
		h.handleGetConnection(w, r, path)
	case r.Method == http.MethodGet && path == "/api/v2/logs":
		h.handleListLogs(w, r)
	case r.Method == http.MethodGet && path == "/api/v2/organizations":
		h.handleListOrganizations(w, r)
	case r.Method == http.MethodPost && path == "/api/v2/organizations":
		h.handleCreateOrganization(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/organizations/") && !strings.Contains(strings.TrimPrefix(path, "/api/v2/organizations/"), "/"):
		h.handleGetOrganization(w, r, path)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v2/organizations/") && !strings.Contains(strings.TrimPrefix(path, "/api/v2/organizations/"), "/"):
		h.handlePatchOrganization(w, r, path)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/v2/organizations/") && !strings.Contains(strings.TrimPrefix(path, "/api/v2/organizations/"), "/"):
		h.handleDeleteOrganization(w, r, path)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/members") && strings.HasPrefix(path, "/api/v2/organizations/"):
		h.handleListOrgMembers(w, r, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/members") && strings.HasPrefix(path, "/api/v2/organizations/"):
		h.handleAddOrgMember(w, r, path)
	case r.Method == http.MethodDelete && strings.HasSuffix(path, "/members") && strings.HasPrefix(path, "/api/v2/organizations/"):
		h.handleRemoveOrgMember(w, r, path)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/connections") && strings.HasPrefix(path, "/api/v2/organizations/"):
		h.handleListOrgConnections(w, r, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/connections") && strings.HasPrefix(path, "/api/v2/organizations/"):
		h.handleAddOrgConnection(w, r, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/invitations") && strings.HasPrefix(path, "/api/v2/organizations/"):
		h.handleCreateOrgInvitation(w, r, path)
	case r.Method == http.MethodGet && path == "/organizations/accept-invitation":
		h.handleAcceptInvitation(w, r)
	case tokenvault.Enabled() && r.Method == http.MethodPost && path == "/api/v2/token-vault":
		h.handleTokenVaultStore(w, r)
	case tokenvault.Enabled() && r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/token-vault/"):
		h.handleTokenVaultGet(w, r, path)
	default:
		http.NotFound(w, r)
	}
}

// handleHealth is backward-compatible: same as /ready (DB+Redis checks).
// Returns 200 when healthy, 503 when any check fails.
func (h *Handlers) handleHealth(w http.ResponseWriter, r *http.Request) {
	h.handleReady(w, r)
}

// handleLive is minimal liveness for K8s: returns 200 if process is up.
// Use for livenessProbe; no dependency checks.
func (h *Handlers) handleLive(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleReady is readiness for K8s: checks DB and Redis (if used).
// Returns 503 if not ready. Use for readinessProbe.
func (h *Handlers) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	checks := make(map[string]string)

	if err := h.Store.Ping(ctx); err != nil {
		checks["database"] = err.Error()
	}
	if h.RedisClient != nil {
		if err := h.RedisClient.Ping(ctx).Err(); err != nil {
			checks["redis"] = err.Error()
		}
	}

	if len(checks) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "unhealthy",
			"checks": checks,
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handlers) handleMetrics(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

func (h *Handlers) parseTokenParams(r *http.Request) map[string]string {
	out := make(map[string]string)
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var params map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&params); err == nil {
			for k, v := range params {
				if s, ok := v.(string); ok {
					out[k] = s
				}
			}
		}
	} else {
		_ = r.ParseForm()
		for k, v := range r.Form {
			if len(v) > 0 {
				out[k] = v[0]
			}
		}
	}
	return out
}

func (h *Handlers) handleToken(w http.ResponseWriter, r *http.Request) {
	p := h.parseTokenParams(r)
	grantType := p["grant_type"]
	clientID := p["client_id"]
	if clientID == "" {
		clientID = "e2e-test"
	}
	// FAPI: require PKCE for authorization_code when FAPI enabled
	if fapi.Enabled() && grantType == "authorization_code" {
		if p["code_verifier"] == "" {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "FAPI requires PKCE code_verifier for authorization_code"})
			return
		}
	}
	switch grantType {
	case "client_credentials":
		h.handleClientCredentials(w, r, clientID)
		return
	case "http://auth0.com/oauth/grant-type/password-realm", "password":
		h.handlePasswordGrant(w, r, p["username"], p["password"], clientID, p["scope"], p["audience"])
		return
	case "authorization_code":
		h.handleAuthorizationCode(w, r, p["code"], p["redirect_uri"], p["client_id"], p["client_secret"], p["code_verifier"])
		return
	case "refresh_token":
		h.handleRefreshToken(w, r, p["refresh_token"], p["client_id"])
		return
	case "urn:ietf:params:oauth:grant-type:device_code":
		h.handleDeviceCodeToken(w, r, p["device_code"], clientID)
		return
	case cibaGrantType:
		h.handleCIBAToken(w, r, p["auth_req_id"], clientID)
		return
	default:
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (h *Handlers) handlePasswordGrant(w http.ResponseWriter, r *http.Request, username, password, clientID, scope, audience string) {
	if username == "" || password == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Wrong email or password."})
		return
	}
	// Brute-force lockout check (by email/username)
	if lockedUntil, locked := h.Store.IsLockedOut(r.Context(), username); locked {
		sendJSON(w, http.StatusTooManyRequests, map[string]string{
			"error":             "too_many_attempts",
			"error_description": "Account temporarily locked. Try again after " + lockedUntil.Format(time.RFC3339) + ".",
		})
		return
	}
	u, err := h.Store.GetByEmail(r.Context(), username)
	if err != nil || u == nil {
		h.Store.RecordFailedLogin(r.Context(), username)
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Wrong email or password."})
		return
	}
	if !h.Store.VerifyPassword(u.PasswordHash, password) {
		h.Store.RecordFailedLogin(r.Context(), username)
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Wrong email or password."})
		return
	}
	// Success: clear failed login attempts
	h.Store.ClearFailedLogins(r.Context(), username)

	// MFA challenge: if MFA enabled, user has MFA, and GrantStore available, require MFA code
	if h.MFAEnabled && h.GrantStore != nil {
		en, _ := h.Store.GetMFAEnrollment(r.Context(), u.ID)
		if en != nil && en.TOTPSecret != "" {
			// Adaptive MFA: skip MFA if IP known and (for web) session present
			if h.AdaptiveMFAEnabled {
				ip := clientIP(r)
				hasSession := false
				if h.SessionStore != nil {
					if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
						if sess, ok := h.SessionStore.Get(c.Value); ok && sess != nil {
							hasSession = true
						}
					}
				}
				ipKnown, _ := h.Store.IsIPKnownForUser(r.Context(), u.ID, ip)
				if ipKnown || hasSession {
					// Not risky: skip MFA challenge
				} else {
					// Risky: require MFA
					challengeID := "mfa_" + uuid.New().String()
					h.GrantStore.SaveMFAPending(challengeID, &grants.MFAPending{
						UserID:   u.ID,
						ClientID: clientID,
						Scope:    scope,
						Audience: audience,
						ClientIP: ip,
					})
					sendJSON(w, http.StatusOK, map[string]interface{}{
						"error":             "mfa_required",
						"error_description": "Multi-factor authentication required",
						"challenge_id":      challengeID,
					})
					return
				}
			} else {
				// Non-adaptive: always require MFA
				challengeID := "mfa_" + uuid.New().String()
				h.GrantStore.SaveMFAPending(challengeID, &grants.MFAPending{
					UserID:   u.ID,
					ClientID: clientID,
					Scope:    scope,
					Audience: audience,
					ClientIP: clientIP(r),
				})
				sendJSON(w, http.StatusOK, map[string]interface{}{
					"error":             "mfa_required",
					"error_description": "Multi-factor authentication required",
					"challenge_id":      challengeID,
				})
				return
			}
		}
	}

	ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
	if h.RulesRunner != nil {
		ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: clientID, Connection: "Username-Password-Authentication", Protocol: "oidc-basic-profile"})
	}
	email, displayName := ruleUser.Email, ruleUser.Name
	if displayName == "" {
		displayName = ruleUser.Nickname
	}
	if displayName == "" {
		displayName = email
	}
	aud := audience
	if aud == "" {
		aud = "https://api.example.com"
	}
	if aud == "" && clientID != "" {
		aud = clientID
	}
	accessLifetime := h.accessTokenLifetime()
	idLifetime := h.idTokenLifetime()
	sessionID := "sid_" + uuid.New().String()
	accessTok, err := h.Issuer.Issue(u.ID, aud, clientID, accessLifetime, ruleUser.AccessTokenClaims)
	if err != nil {
		metrics.TokenRequests.WithLabelValues("password", "error").Inc()
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	metrics.TokenRequests.WithLabelValues("password", "success").Inc()
	audit.LogToken("password", u.ID, clientID, true, nil)
	resp := map[string]interface{}{
		"access_token": accessTok,
		"token_type":   "Bearer",
		"expires_in":   accessLifetime,
	}
	if strings.Contains(scope, "openid") {
		opts := &token.IDTokenOptions{
			AMR:       []string{"pwd"},
			SessionID: sessionID,
			CustomClaims: ruleUser.IDTokenClaims,
		}
		idTok, err := h.Issuer.IssueIDToken(u.ID, aud, clientID, idLifetime, scope, email, displayName, "", opts)
		if err == nil {
			resp["id_token"] = idTok
		}
	}
	if strings.Contains(scope, "offline_access") && h.GrantStore != nil {
		refreshTok := "rt_" + uuid.New().String()
		h.GrantStore.SaveRefreshToken(refreshTok, &grants.RefreshGrant{UserID: u.ID, ClientID: clientID, Scope: scope, SessionID: sessionID})
		resp["refresh_token"] = refreshTok
	}
	sendJSON(w, http.StatusOK, resp)
}

func (h *Handlers) handleClientCredentials(w http.ResponseWriter, r *http.Request, clientID string) {
	accessLifetime := h.accessTokenLifetime()
	tok, err := h.Issuer.Issue("client|"+clientID, "https://api.example.com", clientID, accessLifetime, nil)
	if err != nil {
		metrics.TokenRequests.WithLabelValues("client_credentials", "error").Inc()
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	metrics.TokenRequests.WithLabelValues("client_credentials", "success").Inc()
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   accessLifetime,
	})
}

func (h *Handlers) handleAuthorizationCode(w http.ResponseWriter, r *http.Request, code, redirectURI, clientID, clientSecret, codeVerifier string) {
	if h.GrantStore == nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Authorization code flow not configured"})
		return
	}
	if code == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Missing authorization code"})
		return
	}
	ac, ok := h.GrantStore.ConsumeCode(code)
	if !ok {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid or expired authorization code"})
		return
	}
	if clientID != "" && ac.ClientID != clientID {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Client ID mismatch"})
		return
	}
	if redirectURI != "" && ac.RedirectURI != redirectURI {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Redirect URI mismatch"})
		return
	}
	// PKCE: if code was issued with challenge, verifier is required
	if ac.CodeChallenge != "" {
		if err := pkce.Verify(codeVerifier, ac.CodeChallenge, ac.CodeChallengeMethod); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": err.Error()})
			return
		}
	}
	// Client secret for confidential clients
	if h.ClientRegistry != nil && h.ClientRegistry.RequireSecretForCodes && h.ClientRegistry.IsConfidential(ac.ClientID) {
		if !h.ClientRegistry.ValidateSecret(ac.ClientID, clientSecret) {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "Invalid client_secret"})
			return
		}
	}
	effectiveClientID := ac.ClientID
	if clientID != "" {
		effectiveClientID = clientID
	}
	aud := ac.Audience
	if aud == "" {
		aud = "https://api.example.com"
	}
	if aud == "" && effectiveClientID != "" {
		aud = effectiveClientID
	}
	u, err := h.Store.GetByID(r.Context(), ac.UserID)
	if err != nil || u == nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
	if h.RulesRunner != nil {
		ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: effectiveClientID, Connection: "Username-Password-Authentication", Protocol: "oidc-basic-profile"})
	}
	email, displayName := ruleUser.Email, ruleUser.Name
	if displayName == "" {
		displayName = ruleUser.Nickname
	}
	if displayName == "" {
		displayName = email
	}
	accessLifetime := h.accessTokenLifetime()
	idLifetime := h.idTokenLifetime()
	sessionID := ac.SessionID
	if sessionID == "" {
		sessionID = "sid_" + uuid.New().String()
	}
	accessTok, err := h.Issuer.Issue(u.ID, aud, effectiveClientID, accessLifetime, ruleUser.AccessTokenClaims)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	resp := map[string]interface{}{
		"access_token": accessTok,
		"token_type":   "Bearer",
		"expires_in":   accessLifetime,
	}
	if strings.Contains(ac.Scope, "openid") {
		opts := &token.IDTokenOptions{
			Nonce:        ac.Nonce,
			AMR:          []string{"pwd"},
			AccessToken:  accessTok,
			AuthCode:     code,
			SessionID:    sessionID,
			CustomClaims: ruleUser.IDTokenClaims,
		}
		idTok, err := h.Issuer.IssueIDToken(u.ID, aud, effectiveClientID, idLifetime, ac.Scope, email, displayName, "", opts)
		if err == nil {
			resp["id_token"] = idTok
		}
	}
	if strings.Contains(ac.Scope, "offline_access") && h.GrantStore != nil {
		refreshTok := "rt_" + uuid.New().String()
		h.GrantStore.SaveRefreshToken(refreshTok, &grants.RefreshGrant{UserID: u.ID, ClientID: effectiveClientID, Scope: ac.Scope, SessionID: sessionID})
		resp["refresh_token"] = refreshTok
	}
	metrics.TokenRequests.WithLabelValues("authorization_code", "success").Inc()
	audit.LogToken("authorization_code", u.ID, effectiveClientID, true, nil)
	sendJSON(w, http.StatusOK, resp)
}

func (h *Handlers) handleRefreshToken(w http.ResponseWriter, r *http.Request, refreshToken, clientID string) {
	if h.GrantStore == nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Refresh token flow not configured"})
		return
	}
	if refreshToken == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Missing refresh token"})
		return
	}
	rg, ok := h.GrantStore.ConsumeRefreshToken(refreshToken)
	if !ok {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid or expired refresh token"})
		return
	}
	if clientID != "" && rg.ClientID != clientID {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Client ID mismatch"})
		return
	}
	aud := "https://api.example.com"
	if rg.ClientID != "" {
		aud = rg.ClientID
	}
	accessLifetime := h.accessTokenLifetime()
	idLifetime := h.idTokenLifetime()
	sessionID := rg.SessionID
	if sessionID == "" {
		sessionID = "sid_" + uuid.New().String()
	}
	accessTok, err := h.Issuer.Issue(rg.UserID, aud, rg.ClientID, accessLifetime, nil)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	resp := map[string]interface{}{
		"access_token": accessTok,
		"token_type":   "Bearer",
		"expires_in":   accessLifetime,
	}
	if strings.Contains(rg.Scope, "openid") {
		u, _ := h.Store.GetByID(r.Context(), rg.UserID)
		email, name := "", ""
		if u != nil {
			email, name = u.Email, u.DisplayName
		}
		opts := &token.IDTokenOptions{AMR: []string{"pwd"}, SessionID: sessionID}
		idTok, err := h.Issuer.IssueIDToken(rg.UserID, aud, rg.ClientID, idLifetime, rg.Scope, email, name, "", opts)
		if err == nil {
			resp["id_token"] = idTok
		}
	}
	// Token rotation: issue new refresh token
	if strings.Contains(rg.Scope, "offline_access") {
		newRefresh := "rt_" + uuid.New().String()
		h.GrantStore.SaveRefreshToken(newRefresh, &grants.RefreshGrant{UserID: rg.UserID, ClientID: rg.ClientID, Scope: rg.Scope, SessionID: sessionID})
		resp["refresh_token"] = newRefresh
	}
	metrics.TokenRequests.WithLabelValues("refresh_token", "success").Inc()
	audit.LogToken("refresh_token", rg.UserID, rg.ClientID, true, nil)
	sendJSON(w, http.StatusOK, resp)
}

func (h *Handlers) handleRevoke(w http.ResponseWriter, r *http.Request) {
	p := h.parseTokenParams(r)
	tok := p["token"]
	tokenTypeHint := p["token_type_hint"]
	if tok == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if tokenTypeHint == "refresh_token" || strings.HasPrefix(tok, "rt_") {
		if h.GrantStore != nil {
			h.GrantStore.RevokeRefreshToken(tok)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	p := h.parseTokenParams(r)
	tok := p["token"]
	if tok == "" {
		sendJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}
	claims, err := h.Issuer.Validate(tok)
	if err != nil {
		sendJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}
	active := true
	out := map[string]interface{}{
		"active": active,
		"sub":    claims["sub"],
		"iss":    claims["iss"],
		"aud":    claims["aud"],
		"exp":    claims["exp"],
		"iat":    claims["iat"],
	}
	if azp, ok := claims["azp"].(string); ok {
		out["client_id"] = azp
	}
	if scope, ok := claims["scope"].(string); ok {
		out["scope"] = scope
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleDeviceCodeRequest(w http.ResponseWriter, r *http.Request) {
	p := h.parseTokenParams(r)
	clientID := p["client_id"]
	scope := p["scope"]
	audience := p["audience"]
	if clientID == "" {
		clientID = "e2e-test"
	}
	if scope == "" {
		scope = "openid"
	}
	deviceCode := "dc_" + uuid.New().String()
	userCode := randomUserCode()
	base := h.issuerURL()
	dc := &grants.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:     scope,
		Audience:  audience,
	}
	if h.GrantStore != nil {
		h.GrantStore.SaveDeviceCode(deviceCode, userCode, dc)
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"device_code":              deviceCode,
		"user_code":                userCode,
		"verification_uri":         base + "/oauth/device/authorize",
		"verification_uri_complete": base + "/oauth/device/authorize?user_code=" + url.QueryEscape(userCode),
		"expires_in":               900,
		"interval":                 5,
	})
}

func randomUserCode() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

func (h *Handlers) handleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		userCode = r.FormValue("user_code")
	}
	if userCode == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>user_code is required</p></body></html>`))
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		action := r.FormValue("action")
		username := r.FormValue("username")
		password := r.FormValue("password")
		if action == "deny" {
			if h.GrantStore != nil {
				h.GrantStore.DenyDeviceCode(userCode)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<!DOCTYPE html><html><body><p>Access denied.</p></body></html>`))
			return
		}
		if username == "" || password == "" {
			http.Error(w, "username and password required", http.StatusBadRequest)
			return
		}
		u, err := h.Store.GetByEmail(r.Context(), username)
		if err != nil || u == nil || !h.Store.VerifyPassword(u.PasswordHash, password) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<!DOCTYPE html><html><body><p>Invalid credentials.</p><a href="?user_code=` + html.EscapeString(userCode) + `">Try again</a></body></html>`))
			return
		}
		if h.GrantStore != nil {
			h.GrantStore.AuthorizeDeviceCode(userCode, u.ID)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Device authorized. You can close this page.</p></body></html>`))
		return
	}
	html := `<!DOCTYPE html><html><head><title>Device Authorization</title></head><body>
<p>Enter code: <strong>` + html.EscapeString(userCode) + `</strong></p>
<form method="post" action="?user_code=` + html.EscapeString(userCode) + `">
<input type="hidden" name="user_code" value="` + html.EscapeString(userCode) + `">
<label>Email: <input type="text" name="username"></label><br>
<label>Password: <input type="password" name="password"></label><br>
<button type="submit" name="action" value="allow">Authorize</button>
<button type="submit" name="action" value="deny">Deny</button>
</form></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (h *Handlers) handleDeviceCodeToken(w http.ResponseWriter, r *http.Request, deviceCode, clientID string) {
	if h.GrantStore == nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Device code flow not configured"})
		return
	}
	if deviceCode == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Missing device_code"})
		return
	}
	dc, ok := h.GrantStore.GetDeviceCode(deviceCode)
	if !ok {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid or expired device_code"})
		return
	}
	if dc.AccessDenied {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "access_denied", "error_description": "User denied the request"})
		return
	}
	if !dc.UserAuthorized {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "authorization_pending", "error_description": "User has not yet completed authorization"})
		return
	}
	grant, ok := h.GrantStore.ConsumeDeviceCode(deviceCode)
	if !ok {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid or expired device_code"})
		return
	}
	aud := grant.Audience
	if aud == "" && grant.ClientID != "" {
		aud = grant.ClientID
	}
	if aud == "" {
		aud = "https://api.example.com"
	}
	u, err := h.Store.GetByID(r.Context(), grant.UserID)
	if err != nil || u == nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
	if h.RulesRunner != nil {
		ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: grant.ClientID, Connection: "Username-Password-Authentication", Protocol: "oidc-basic-profile"})
	}
	email, displayName := ruleUser.Email, ruleUser.Name
	if displayName == "" {
		displayName = ruleUser.Nickname
	}
	if displayName == "" {
		displayName = email
	}
	accessLifetime := h.accessTokenLifetime()
	idLifetime := h.idTokenLifetime()
	sessionID := "sid_" + uuid.New().String()
	accessTok, err := h.Issuer.Issue(grant.UserID, aud, grant.ClientID, accessLifetime, ruleUser.AccessTokenClaims)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	resp := map[string]interface{}{
		"access_token": accessTok,
		"token_type":   "Bearer",
		"expires_in":   accessLifetime,
	}
	if strings.Contains(grant.Scope, "openid") {
		opts := &token.IDTokenOptions{AMR: []string{"pwd"}, SessionID: sessionID, CustomClaims: ruleUser.IDTokenClaims}
		idTok, err := h.Issuer.IssueIDToken(grant.UserID, aud, grant.ClientID, idLifetime, grant.Scope, email, displayName, "", opts)
		if err == nil {
			resp["id_token"] = idTok
		}
	}
	sendJSON(w, http.StatusOK, resp)
}

func (h *Handlers) handleImplicitAuthorize(w http.ResponseWriter, r *http.Request, responseType, clientID, redirectURI, scope, state, audience, username, password string, redirectURL *url.URL) {
	wantToken := strings.Contains(responseType, "token") || responseType == "token"
	wantIDToken := strings.Contains(responseType, "id_token") || responseType == "id_token"
	if !wantToken && !wantIDToken {
		wantToken = true
	}
	if username == "" || password == "" {
		loginURL := h.issuerURL() + "/login?client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&scope=" + url.QueryEscape(scope) + "&state=" + url.QueryEscape(state) + "&response_type=" + url.QueryEscape(responseType)
		if audience != "" {
			loginURL += "&audience=" + url.QueryEscape(audience)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	u, err := h.Store.GetByEmail(r.Context(), username)
	if err != nil || u == nil || !h.Store.VerifyPassword(u.PasswordHash, password) {
		q := redirectURL.Query()
		q.Set("error", "access_denied")
		q.Set("error_description", "invalid_credentials")
		if state != "" {
			q.Set("state", state)
		}
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String()+"#"+q.Encode(), http.StatusFound)
		return
	}
	aud := audience
	if aud == "" && clientID != "" {
		aud = clientID
	}
	if aud == "" {
		aud = "https://api.example.com"
	}
	ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
	if h.RulesRunner != nil {
		ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: clientID, Connection: "Username-Password-Authentication", Protocol: "oidc-basic-profile"})
	}
	email, displayName := ruleUser.Email, ruleUser.Name
	if displayName == "" {
		displayName = ruleUser.Nickname
	}
	if displayName == "" {
		displayName = email
	}
	accessLifetime := h.accessTokenLifetime()
	idLifetime := h.idTokenLifetime()
	var frag []string
	if wantToken {
		accessTok, err := h.Issuer.Issue(u.ID, aud, clientID, accessLifetime, ruleUser.AccessTokenClaims)
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		frag = append(frag, "access_token="+url.QueryEscape(accessTok), "token_type=Bearer", "expires_in="+strconv.Itoa(accessLifetime))
	}
	if wantIDToken {
		opts := &token.IDTokenOptions{AMR: []string{"pwd"}, CustomClaims: ruleUser.IDTokenClaims}
		idTok, err := h.Issuer.IssueIDToken(u.ID, aud, clientID, idLifetime, scope, email, displayName, "", opts)
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		frag = append(frag, "id_token="+url.QueryEscape(idTok))
	}
	if state != "" {
		frag = append(frag, "state="+url.QueryEscape(state))
	}
	dest := redirectURL.String()
	if redirectURL.RawQuery != "" {
		dest = strings.TrimSuffix(dest, "?"+redirectURL.RawQuery)
	}
	http.Redirect(w, r, dest+"#"+strings.Join(frag, "&"), http.StatusFound)
}

func (h *Handlers) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	responseType := r.URL.Query().Get("response_type")
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")
	prompt := r.URL.Query().Get("prompt")
	loginHint := r.URL.Query().Get("login_hint")
	nonce := r.URL.Query().Get("nonce")
	audience := r.URL.Query().Get("audience")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}
	orgID := r.URL.Query().Get("organization_id")
	if orgID == "" {
		orgID = r.URL.Query().Get("org")
	}

	// FAPI validation (when enabled)
	if fapi.Enabled() {
		params := map[string]string{
			"code_challenge":        codeChallenge,
			"code_challenge_method": codeChallengeMethod,
			"response_mode":         r.URL.Query().Get("response_mode"),
		}
		if errResp := fapi.ValidateFAPIRequest(r, params, false); errResp != nil {
			sendJSON(w, http.StatusBadRequest, errResp)
			return
		}
	}

	// Redirect URI validation
	if redirectURI == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri is required"})
		return
	}
	if h.ClientRegistry != nil && !h.ClientRegistry.ValidateRedirectURI(clientID, redirectURI) {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri not allowed for this client"})
		return
	}
	if clientID == "" {
		clientID = "e2e-test"
	}
	if scope == "" {
		scope = "openid"
	}
	if h.ClientRegistry != nil && !h.ClientRegistry.ValidateScope(clientID, scope) {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope", "error_description": "requested scope not allowed"})
		return
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid redirect_uri"})
		return
	}

	// Self-service SSO: if login_hint or username has email domain matching enterprise_connection.domain_hint, redirect to that IdP
	emailForDomain := loginHint
	if emailForDomain == "" {
		emailForDomain = username
	}
	if emailForDomain != "" {
		if idx := strings.Index(emailForDomain, "@"); idx >= 0 {
			domain := strings.ToLower(strings.TrimSpace(emailForDomain[idx+1:]))
			if domain != "" {
				ec, err := h.Store.GetEnterpriseConnectionByDomain(r.Context(), domain)
				if err == nil && ec != nil && h.GrantStore != nil {
					oauthState := "ent_" + uuid.New().String()
					h.GrantStore.SaveSocialState(oauthState, &grants.SocialState{
						RedirectURI:         redirectURI,
						ClientID:            clientID,
						Scope:               scope,
						State:               state,
						Nonce:               nonce,
						CodeChallenge:       codeChallenge,
						CodeChallengeMethod: codeChallengeMethod,
						Audience:            audience,
						ResponseType:        responseType,
						Connection:          "enterprise:" + ec.ID,
					})
					authURL, err := buildEnterpriseOIDCAuthURL(ec, strings.TrimSuffix(h.issuerURL(), "/")+"/callback/enterprise", clientID, scope, oauthState)
					if err == nil && authURL != "" {
						http.Redirect(w, r, authURL, http.StatusFound)
						return
					}
				}
			}
		}
	}

	// Enterprise OIDC: connection=okta (or name) redirects to enterprise IdP
	connection := r.URL.Query().Get("connection")
	if ec, err := h.Store.GetOIDCEnterpriseConnectionByName(r.Context(), connection); err == nil && ec != nil && h.GrantStore != nil {
		oauthState := "ent_" + uuid.New().String()
		callbackURL := strings.TrimSuffix(h.issuerURL(), "/") + "/callback/enterprise"
		h.GrantStore.SaveSocialState(oauthState, &grants.SocialState{
			RedirectURI:         redirectURI,
			ClientID:            clientID,
			Scope:               scope,
			State:               state,
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Audience:            audience,
			ResponseType:        responseType,
			Connection:          connection,
		})
		prov := enterprise.NewProvider(&enterprise.OIDCConnection{
			Name: ec.Name, IssuerURL: ec.IssuerURL, ClientID: ec.ClientID,
			ClientSecret: ec.ClientSecret, Scope: ec.Scope, DomainHint: ec.DomainHint,
		})
		authURL := prov.AuthURL(oauthState, callbackURL)
		if authURL != "" {
			http.Redirect(w, r, authURL, http.StatusFound)
			return
		}
	}
	// Social / federation: connection=google|github redirects to provider OAuth
	if prov := social.GetProvider(connection); prov != nil && h.GrantStore != nil {
		oauthState := "soc_" + uuid.New().String()
		callbackURL := strings.TrimSuffix(h.issuerURL(), "/") + "/callback/social"
		h.GrantStore.SaveSocialState(oauthState, &grants.SocialState{
			RedirectURI:         redirectURI,
			ClientID:            clientID,
			Scope:               scope,
			State:               state,
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Audience:            audience,
			ResponseType:        responseType,
			Connection:          connection,
		})
		authURL := prov.AuthURL(oauthState, callbackURL)
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}

	// Passkey (WebAuthn) passwordless: prompt=passkey or connection=webauthn redirects to login with passkey option
	if (prompt == "passkey" || connection == "webauthn") && h.WebAuthnHandler != nil {
		loginURL := h.issuerURL() + "/login?client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&scope=" + url.QueryEscape(scope) + "&prompt=passkey"
		if state != "" {
			loginURL += "&state=" + url.QueryEscape(state)
		}
		if loginHint != "" {
			loginURL += "&login_hint=" + url.QueryEscape(loginHint)
		}
		if audience != "" {
			loginURL += "&audience=" + url.QueryEscape(audience)
		}
		if codeChallenge != "" {
			loginURL += "&code_challenge=" + url.QueryEscape(codeChallenge) + "&code_challenge_method=" + url.QueryEscape(codeChallengeMethod)
		}
		if nonce != "" {
			loginURL += "&nonce=" + url.QueryEscape(nonce)
		}
		if responseType != "" {
			loginURL += "&response_type=" + url.QueryEscape(responseType)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Implicit flow: response_type=token or id_token
	if responseType == "token" || responseType == "id_token" || strings.Contains(responseType, "token") || strings.Contains(responseType, "id_token") {
		h.handleImplicitAuthorize(w, r, responseType, clientID, redirectURI, scope, state, audience, username, password, redirectURL)
		return
	}
	if responseType != "code" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_response_type", "error_description": "Only response_type=code, token, id_token are supported"})
		return
	}
	if username != "" && password != "" {
		if h.GrantStore == nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Authorization code flow not configured"})
			return
		}
		u, err := h.Store.GetByEmail(r.Context(), username)
		if err != nil || u == nil || !h.Store.VerifyPassword(u.PasswordHash, password) {
			metrics.AuthRequests.WithLabelValues("access_denied").Inc()
			q := redirectURL.Query()
			q.Set("error", "access_denied")
			q.Set("error_description", "invalid_credentials")
			if state != "" {
				q.Set("state", state)
			}
			redirectURL.RawQuery = q.Encode()
			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			return
		}
		// Organization: validate user is member when org_id present
		if orgID != "" {
			member, err := h.Store.IsOrgMember(r.Context(), orgID, u.ID)
			if err != nil || !member {
				metrics.AuthRequests.WithLabelValues("access_denied").Inc()
				q := redirectURL.Query()
				q.Set("error", "access_denied")
				q.Set("error_description", "User is not a member of this organization")
				if state != "" {
					q.Set("state", state)
				}
				redirectURL.RawQuery = q.Encode()
				http.Redirect(w, r, redirectURL.String(), http.StatusFound)
				return
			}
		}
		// Connection: when org_id and connection specified, validate connection is allowed for org
		if orgID != "" && connection != "" {
			orgConns, _ := h.Store.ListOrgConnections(r.Context(), orgID)
			entConns, _ := h.Store.ListEnterpriseConnections(r.Context(), orgID)
			allowed := false
			for _, c := range orgConns {
				if c == connection {
					allowed = true
					break
				}
			}
			for _, ec := range entConns {
				if ec.ID == connection || "enterprise:"+ec.ID == connection {
					allowed = true
					break
				}
			}
			if !allowed {
				metrics.AuthRequests.WithLabelValues("access_denied").Inc()
				q := redirectURL.Query()
				q.Set("error", "access_denied")
				q.Set("error_description", "Connection not allowed for this organization")
				if state != "" {
					q.Set("state", state)
				}
				redirectURL.RawQuery = q.Encode()
				http.Redirect(w, r, redirectURL.String(), http.StatusFound)
				return
			}
		}
		metrics.AuthRequests.WithLabelValues("success").Inc()
		if h.SessionStore != nil {
			if sid, err := h.SessionStore.Create(u.ID, u.Email); err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     sessionCookieName,
					Value:    sid,
					Path:     "/",
					MaxAge:   sessionCookieMaxAge,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
		code := "ac_" + uuid.New().String()
		sessionID := "sid_" + uuid.New().String()
		if h.GrantStore != nil {
			h.GrantStore.SaveCode(code, &grants.AuthCode{
				UserID:              u.ID,
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				Scope:               scope,
				Nonce:               nonce,
				SessionID:           sessionID,
				Audience:            audience,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
			})
		}
		q := redirectURL.Query()
		q.Set("code", code)
		if state != "" {
			q.Set("state", state)
		}
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}
	if prompt == "none" && username == "" && password == "" {
		metrics.AuthRequests.WithLabelValues("login_required").Inc()
		q := redirectURL.Query()
		q.Set("error", "login_required")
		q.Set("error_description", "User must be authenticated")
		if state != "" {
			q.Set("state", state)
		}
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}
	// Server-side session: if already authenticated via cookie, issue code and redirect
	if h.SessionStore != nil && username == "" && password == "" {
		if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			if sess, ok := h.SessionStore.Get(c.Value); ok && sess != nil {
				u, err := h.Store.GetByID(r.Context(), sess.UserID)
				if err == nil && u != nil && h.GrantStore != nil {
					// Organization: validate user is member when org_id present
					if orgID != "" {
						member, err := h.Store.IsOrgMember(r.Context(), orgID, u.ID)
						if err != nil || !member {
							metrics.AuthRequests.WithLabelValues("access_denied").Inc()
							q := redirectURL.Query()
							q.Set("error", "access_denied")
							q.Set("error_description", "User is not a member of this organization")
							if state != "" {
								q.Set("state", state)
							}
							redirectURL.RawQuery = q.Encode()
							http.Redirect(w, r, redirectURL.String(), http.StatusFound)
							return
						}
					}
					metrics.AuthRequests.WithLabelValues("success").Inc()
					code := "ac_" + uuid.New().String()
					sessionID := "sid_" + uuid.New().String()
					h.GrantStore.SaveCode(code, &grants.AuthCode{
						UserID:              u.ID,
						ClientID:            clientID,
						RedirectURI:         redirectURI,
						Scope:               scope,
						Nonce:               nonce,
						SessionID:           sessionID,
						Audience:            audience,
						CodeChallenge:       codeChallenge,
						CodeChallengeMethod: codeChallengeMethod,
					})
					q := redirectURL.Query()
					q.Set("code", code)
					if state != "" {
						q.Set("state", state)
					}
					redirectURL.RawQuery = q.Encode()
					http.Redirect(w, r, redirectURL.String(), http.StatusFound)
					return
				}
			}
		}
	}
	metrics.AuthRequests.WithLabelValues("redirect_to_login").Inc()
	loginURL := h.issuerURL() + "/login?client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&scope=" + url.QueryEscape(scope)
	if state != "" {
		loginURL += "&state=" + url.QueryEscape(state)
	}
	if orgID != "" {
		loginURL += "&organization_id=" + url.QueryEscape(orgID)
	}
	if connection != "" {
		loginURL += "&connection=" + url.QueryEscape(connection)
	}
	if loginHint != "" {
		loginURL += "&login_hint=" + url.QueryEscape(loginHint)
	}
	if audience != "" {
		loginURL += "&audience=" + url.QueryEscape(audience)
	}
	if codeChallenge != "" {
		loginURL += "&code_challenge=" + url.QueryEscape(codeChallenge) + "&code_challenge_method=" + url.QueryEscape(codeChallengeMethod)
	}
	if nonce != "" {
		loginURL += "&nonce=" + url.QueryEscape(nonce)
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func getParam(r *http.Request, key string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	return r.FormValue(key)
}

// renderLoginPage returns the login HTML. If LOGIN_PAGE_TEMPLATE is set, loads that file
// and executes it with the given data. Template vars: .ClientID, .RedirectURI, .Scope, .State,
// .ResponseType, .Nonce, .Audience, .CodeChallenge, .CodeChallengeMethod, .LoginHint,
// .OrganizationID, .Connection.
// Custom template must POST to /login with hidden inputs of the same names.
func renderLoginPage(data map[string]string) (string, error) {
	tplPath := os.Getenv("LOGIN_PAGE_TEMPLATE")
	if tplPath != "" {
		body, err := os.ReadFile(tplPath)
		if err != nil {
			return "", err
		}
		t, err := template.New("login").Parse(string(body))
		if err != nil {
			return "", err
		}
		var buf strings.Builder
		if err := t.Execute(&buf, data); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
	// Default login form
	return `<!DOCTYPE html><html><head><title>Login</title></head><body>
<form method="post" action="/login">
<input type="hidden" name="client_id" value="` + html.EscapeString(data["ClientID"]) + `">
<input type="hidden" name="redirect_uri" value="` + html.EscapeString(data["RedirectURI"]) + `">
<input type="hidden" name="scope" value="` + html.EscapeString(data["Scope"]) + `">
<input type="hidden" name="state" value="` + html.EscapeString(data["State"]) + `">
<input type="hidden" name="response_type" value="` + html.EscapeString(data["ResponseType"]) + `">
<input type="hidden" name="nonce" value="` + html.EscapeString(data["Nonce"]) + `">
<input type="hidden" name="audience" value="` + html.EscapeString(data["Audience"]) + `">
<input type="hidden" name="code_challenge" value="` + html.EscapeString(data["CodeChallenge"]) + `">
<input type="hidden" name="code_challenge_method" value="` + html.EscapeString(data["CodeChallengeMethod"]) + `">
<input type="hidden" name="organization_id" value="` + html.EscapeString(data["OrganizationID"]) + `">
<input type="hidden" name="connection" value="` + html.EscapeString(data["Connection"]) + `">
<label>Email: <input type="text" name="username" value="` + html.EscapeString(data["LoginHint"]) + `"></label><br>
<label>Password: <input type="password" name="password"></label><br>
<button type="submit">Log in</button>
</form></body></html>`, nil
}

func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientID := getParam(r, "client_id")
	redirectURI := getParam(r, "redirect_uri")
	scope := getParam(r, "scope")
	state := getParam(r, "state")
	nonce := getParam(r, "nonce")
	audience := getParam(r, "audience")
	responseType := getParam(r, "response_type")
	codeChallenge := getParam(r, "code_challenge")
	codeChallengeMethod := getParam(r, "code_challenge_method")
	orgID := getParam(r, "organization_id")
	if orgID == "" {
		orgID = getParam(r, "org")
	}
	connection := getParam(r, "connection")
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}
	if scope == "" {
		scope = "openid"
	}
	if redirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		if orgID == "" {
			orgID = r.FormValue("organization_id")
		}
		if connection == "" {
			connection = r.FormValue("connection")
		}
		if username == "" || password == "" {
			http.Error(w, "username and password required", http.StatusBadRequest)
			return
		}
		u, err := h.Store.GetByEmail(r.Context(), username)
		if err != nil || u == nil || !h.Store.VerifyPassword(u.PasswordHash, password) {
			metrics.LoginAttempts.WithLabelValues("failed").Inc()
			audit.LogLogin("", username, clientID, false, map[string]interface{}{"reason": "invalid_credentials"})
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		if orgID != "" {
			member, err := h.Store.IsOrgMember(r.Context(), orgID, u.ID)
			if err != nil || !member {
				metrics.LoginAttempts.WithLabelValues("failed").Inc()
				audit.LogLogin(u.ID, username, clientID, false, map[string]interface{}{"reason": "not_org_member"})
				http.Error(w, "User is not a member of this organization", http.StatusForbidden)
				return
			}
		}
		metrics.LoginAttempts.WithLabelValues("success").Inc()
		audit.LogLogin(u.ID, u.Email, clientID, true, nil)
		if h.SessionStore != nil {
			if sid, err := h.SessionStore.Create(u.ID, u.Email); err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     sessionCookieName,
					Value:    sid,
					Path:     "/",
					MaxAge:   sessionCookieMaxAge,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
		redirectURL, _ := url.Parse(redirectURI)
		wantToken := responseType == "token" || strings.Contains(responseType, "token")
		wantIDToken := responseType == "id_token" || strings.Contains(responseType, "id_token")
		if wantToken || wantIDToken {
			aud := audience
			if aud == "" && clientID != "" {
				aud = clientID
			}
			if aud == "" {
				aud = "https://api.example.com"
			}
			ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
			if h.RulesRunner != nil {
				ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: clientID, Connection: "Username-Password-Authentication", Protocol: "oidc-basic-profile"})
			}
			email, displayName := ruleUser.Email, ruleUser.Name
			if displayName == "" {
				displayName = ruleUser.Nickname
			}
			if displayName == "" {
				displayName = email
			}
			accessLifetime := h.accessTokenLifetime()
			idLifetime := h.idTokenLifetime()
			var frag []string
			if wantToken {
				accessTok, err := h.Issuer.Issue(u.ID, aud, clientID, accessLifetime, ruleUser.AccessTokenClaims)
				if err != nil {
					http.Error(w, "server error", http.StatusInternalServerError)
					return
				}
				frag = append(frag, "access_token="+url.QueryEscape(accessTok), "token_type=Bearer", "expires_in="+strconv.Itoa(accessLifetime))
			}
			if wantIDToken {
				opts := &token.IDTokenOptions{AMR: []string{"pwd"}, CustomClaims: ruleUser.IDTokenClaims}
				idTok, err := h.Issuer.IssueIDToken(u.ID, aud, clientID, idLifetime, scope, email, displayName, "", opts)
				if err != nil {
					http.Error(w, "server error", http.StatusInternalServerError)
					return
				}
				frag = append(frag, "id_token="+url.QueryEscape(idTok))
			}
			if state != "" {
				frag = append(frag, "state="+url.QueryEscape(state))
			}
			dest := redirectURL.String()
			if redirectURL.RawQuery != "" {
				dest = strings.TrimSuffix(dest, "?"+redirectURL.RawQuery)
			}
			http.Redirect(w, r, dest+"#"+strings.Join(frag, "&"), http.StatusFound)
			return
		}
		if h.GrantStore == nil {
			http.Error(w, "Authorization code flow not configured", http.StatusInternalServerError)
			return
		}
		code := "ac_" + uuid.New().String()
		sessionID := "sid_" + uuid.New().String()
		h.GrantStore.SaveCode(code, &grants.AuthCode{
			UserID:              u.ID,
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scope:               scope,
			Nonce:               nonce,
			SessionID:           sessionID,
			Audience:            audience,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
		})
		q := redirectURL.Query()
		q.Set("code", code)
		if state != "" {
			q.Set("state", state)
		}
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}
	loginHint := getParam(r, "login_hint")
	loginHTML, err := renderLoginPage(map[string]string{
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"Scope":               scope,
		"State":               state,
		"ResponseType":        responseType,
		"Nonce":               nonce,
		"Audience":            audience,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod":  codeChallengeMethod,
		"LoginHint":            loginHint,
		"OrganizationID":       orgID,
		"Connection":           connection,
	})
	if err != nil {
		http.Error(w, "login template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(loginHTML))
}

func (h *Handlers) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email        string                 `json:"email"`
		Password     string                 `json:"password"`
		Connection   string                 `json:"connection"`
		UserMetadata map[string]interface{} `json:"user_metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_body", "description": "Invalid JSON"})
		return
	}
	if req.Email == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_signup", "description": "Email required"})
		return
	}
	if req.Password == "" {
		req.Password = "password123"
	}
	if err := password.Validate(req.Password); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_password", "description": err.Error()})
		return
	}
	if password.IsBreachedCheckEnabled() {
		if err := password.IsBreached(req.Password); err != nil {
			if err == password.ErrBreached {
				sendJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_password", "description": "This password has been found in a data breach and cannot be used. Please choose a different password."})
				return
			}
			sendJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "breach_check_failed", "description": "Unable to verify password. Please try again later."})
			return
		}
	}
	orgID, entID := 1, 1
	role := "user"
	if req.UserMetadata != nil {
		if v, ok := req.UserMetadata["sign_up_enterprise_id"]; ok {
			if n, ok := toInt(v); ok {
				entID = n
			}
		}
		if v, ok := req.UserMetadata["sign_up_role"]; ok {
			if s, ok := v.(string); ok {
				role = s
			}
		}
	}
	uid := "auth0|" + uuid.New().String()
	displayName := req.Email
	if i := strings.Index(req.Email, "@"); i > 0 {
		displayName = req.Email[:i]
	}
	emailVerified := handlersEmailVerificationRequired() == false // default verified when verification not required
	u := &store.User{
		ID:             uid,
		Email:          req.Email,
		DisplayName:    displayName,
		EmailVerified:  emailVerified,
		OrganizationID: orgID,
		EnterpriseID:   entID,
		Role:           role,
	}
	if err := h.Store.CreateUser(r.Context(), u, req.Password); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate") {
			sendJSON(w, http.StatusBadRequest, map[string]string{"code": "user_exists", "description": "User already exists."})
			return
		}
		sendJSON(w, http.StatusInternalServerError, map[string]string{"code": "signup_failed", "description": err.Error()})
		return
	}
	metrics.Signups.Inc()
	audit.LogSignup(u.ID, req.Email, nil)
	sendJSON(w, http.StatusCreated, map[string]string{"email": req.Email, "_id": u.ID})
}

func (h *Handlers) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email      string `json:"email"`
		Connection string `json:"connection"`
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&req)
	} else {
		_ = r.ParseForm()
		req.Email = r.FormValue("email")
		req.Connection = r.FormValue("connection")
	}
	if req.Email == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Email required"})
		return
	}
	u, err := h.Store.GetByEmail(r.Context(), req.Email)
	if err != nil || u == nil {
		// Don't reveal if user exists - always return success for Auth0 compatibility
		sendJSON(w, http.StatusOK, map[string]string{"email": req.Email})
		return
	}
	expiresAt := time.Now().Add(1 * time.Hour)
	token, err := h.Store.CreatePasswordResetToken(r.Context(), u.ID, expiresAt)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// In dev, optionally return token for testing (e.g. EMAIL_VERIFICATION_DEV_RETURN_TOKEN)
	if os.Getenv("PASSWORD_RESET_DEV_RETURN_TOKEN") == "true" {
		sendJSON(w, http.StatusOK, map[string]interface{}{"email": req.Email, "reset_token": token})
		return
	}
	// Production: would send email here. For now just acknowledge.
	sendJSON(w, http.StatusOK, map[string]string{"email": req.Email})
}

func (h *Handlers) handlePasswordlessStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email        string `json:"email"`
		PhoneNumber  string `json:"phone_number"`
		Phone        string `json:"phone"`
		AuthType     string `json:"auth_type"`
		ClientID     string `json:"client_id"`
		RedirectURI  string `json:"redirect_uri"`
		State        string `json:"state"`
		ResponseType string `json:"response_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid JSON"})
		return
	}
	if req.AuthType == "sms" {
		h.handlePasswordlessStartSMS(w, r, &req)
		return
	}
	// magiclink (default)
	if req.Email == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "email is required"})
		return
	}
	if req.AuthType != "magiclink" && req.AuthType != "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "auth_type must be magiclink or sms"})
		return
	}
	if req.ClientID == "" {
		req.ClientID = "e2e-test"
	}
	if req.RedirectURI == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri is required"})
		return
	}
	if h.ClientRegistry != nil && !h.ClientRegistry.ValidateRedirectURI(req.ClientID, req.RedirectURI) {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri not allowed for this client"})
		return
	}
	if req.ResponseType == "" {
		req.ResponseType = "code"
	}

	data := &store.MagicLinkTokenData{
		Email:        req.Email,
		ClientID:     req.ClientID,
		RedirectURI:  req.RedirectURI,
		State:        req.State,
		ResponseType: req.ResponseType,
		Scope:        "openid profile",
		Audience:     "",
	}
	token, err := h.Store.CreateMagicLinkToken(r.Context(), data)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	base := h.issuerURL()
	link := base + "/passwordless/verify?token=" + url.QueryEscape(token)
	if req.State != "" {
		link += "&state=" + url.QueryEscape(req.State)
	}

	devReturn := os.Getenv("MAGIC_LINK_DEV_RETURN_TOKEN") == "true"
	if devReturn {
		sendJSON(w, http.StatusOK, map[string]interface{}{
			"email":   req.Email,
			"_id":     req.Email,
			"request": "magiclink",
			"token":   token,
			"link":    link,
		})
		return
	}

	smtpCfg := email.LoadFromEnv()
	if smtpCfg != nil {
		if err := smtpCfg.SendMagicLink(req.Email, link); err != nil {
			audit.Log(audit.Event{Type: "magic_link_email_failed", ClientID: req.ClientID, Success: false, Details: map[string]interface{}{"error": err.Error()}})
		}
	}

	sendJSON(w, http.StatusOK, map[string]interface{}{
		"email":   req.Email,
		"_id":     req.Email,
		"request": "magiclink",
	})
}

func (h *Handlers) handlePasswordlessStartSMS(w http.ResponseWriter, r *http.Request, req *struct {
	Email        string `json:"email"`
	PhoneNumber  string `json:"phone_number"`
	Phone        string `json:"phone"`
	AuthType     string `json:"auth_type"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	State        string `json:"state"`
	ResponseType string `json:"response_type"`
}) {
	phone := req.PhoneNumber
	if phone == "" {
		phone = req.Phone
	}
	if phone == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "phone_number is required for auth_type=sms"})
		return
	}
	if req.ClientID == "" {
		req.ClientID = "e2e-test"
	}
	if req.RedirectURI == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri is required"})
		return
	}
	if h.ClientRegistry != nil && !h.ClientRegistry.ValidateRedirectURI(req.ClientID, req.RedirectURI) {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri not allowed for this client"})
		return
	}
	if req.ResponseType == "" {
		req.ResponseType = "code"
	}
	code := randomOTP6()
	data := &store.SMSOTPTokenData{
		Phone:        phone,
		Code:         code,
		ClientID:     req.ClientID,
		RedirectURI:  req.RedirectURI,
		State:        req.State,
		ResponseType: req.ResponseType,
		Scope:        "openid profile",
		Audience:     "",
	}
	token, err := h.Store.CreateSMSOTPToken(r.Context(), data)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := sms.SendOTP(phone, code); err != nil {
		audit.Log(audit.Event{Type: "sms_otp_send_failed", ClientID: req.ClientID, Success: false, Details: map[string]interface{}{"error": err.Error()}})
	}
	devReturn := os.Getenv("SMS_OTP_DEV_RETURN_CODE") == "true"
	resp := map[string]interface{}{
		"phone_number": phone,
		"_id":          phone,
		"request":      "sms",
	}
	if devReturn {
		resp["code"] = code
		resp["token"] = token
	}
	sendJSON(w, http.StatusOK, resp)
}

func randomOTP6() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	c := int(n.Int64())
	if c < 100000 {
		c += 100000
	}
	return strconv.Itoa(c)
}

func (h *Handlers) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid JSON"})
		return
	}
	if req.Email == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Email required"})
		return
	}
	u, err := h.Store.GetByEmail(r.Context(), req.Email)
	if err != nil || u == nil {
		sendJSON(w, http.StatusOK, map[string]string{"message": "If that email exists, a reset link has been sent."})
		return
	}
	expiresAt := time.Now().Add(1 * time.Hour)
	token, err := h.Store.CreatePasswordResetToken(r.Context(), u.ID, expiresAt)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if os.Getenv("PASSWORD_RESET_DEV_RETURN_TOKEN") == "true" {
		sendJSON(w, http.StatusOK, map[string]interface{}{"email": req.Email, "reset_token": token})
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"message": "If that email exists, a reset link has been sent."})
}

func (h *Handlers) handlePasswordlessVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Token is required.</p></body></html>`))
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	// Magic link: token prefix magic_
	if strings.HasPrefix(token, "magic_") {
		h.handleMagicLinkVerify(w, r, token, state)
		return
	}

	// SMS OTP: token prefix sms_
	if strings.HasPrefix(token, "sms_") {
		if code == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`<!DOCTYPE html><html><body><p>Code is required for SMS verification. Use ?token=...&code=123456</p></body></html>`))
			return
		}
		h.handleSMSOTPVerify(w, r, token, code, state)
		return
	}

	// Password reset: token prefix prt_
	userID, ok := h.Store.ValidatePasswordResetToken(r.Context(), token)
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Invalid or expired token.</p></body></html>`))
		return
	}
	_ = userID
	base := h.issuerURL()
	html := `<!DOCTYPE html><html><head><title>Reset Password</title></head><body>
<h2>Reset your password</h2>
<form method="post" action="` + base + `/passwordless/confirm">
<input type="hidden" name="token" value="` + html.EscapeString(token) + `">
<label>New password: <input type="password" name="new_password" minlength="8" required></label><br>
<button type="submit">Submit</button>
</form></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (h *Handlers) handleSMSOTPVerify(w http.ResponseWriter, r *http.Request, tokenStr, code, queryState string) {
	data, ok := h.Store.ConsumeSMSOTPToken(r.Context(), tokenStr, code)
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Invalid or expired SMS code.</p></body></html>`))
		return
	}
	redirectURI := data.RedirectURI
	state := data.State
	if queryState != "" {
		state = queryState
	}
	u, err := h.Store.GetByPhone(r.Context(), data.Phone)
	if err != nil || u == nil {
		u = &store.User{
			ID:            "auth0|" + uuid.New().String(),
			Email:         "sms:" + data.Phone,
			PhoneNumber:   data.Phone,
			PasswordHash:  "",
			DisplayName:   data.Phone,
			EmailVerified: false,
		}
		placeholder := "x" + uuid.New().String()
		if err := h.Store.CreateUser(r.Context(), u, placeholder); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		audit.LogSignup(u.ID, data.Phone, nil)
	}
	if h.SessionStore != nil {
		if sessionID, err := h.SessionStore.Create(u.ID, u.Email); err == nil {
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    sessionID,
				Path:     "/",
				MaxAge:   sessionCookieMaxAge,
				HttpOnly: true,
				Secure:   strings.HasPrefix(h.issuerURL(), "https://"),
				SameSite: http.SameSiteLaxMode,
			})
		}
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid redirect_uri"})
		return
	}
	aud := data.Audience
	if aud == "" && data.ClientID != "" {
		aud = data.ClientID
	}
	if aud == "" {
		aud = "https://api.example.com"
	}
	ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
	if h.RulesRunner != nil {
		ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: data.ClientID, Connection: "sms", Protocol: "oidc-basic-profile"})
	}
	emailVal, displayName := ruleUser.Email, ruleUser.Name
	if displayName == "" {
		displayName = ruleUser.Nickname
	}
	if displayName == "" {
		displayName = emailVal
	}
	if displayName == "" {
		displayName = data.Phone
	}
	respType := data.ResponseType
	if respType == "" {
		respType = "code"
	}
	if strings.Contains(respType, "token") || strings.Contains(respType, "id_token") {
		var frag []string
		if strings.Contains(respType, "token") {
			accessTok, err := h.Issuer.Issue(u.ID, aud, data.ClientID, h.accessTokenLifetime(), ruleUser.AccessTokenClaims)
			if err == nil {
				frag = append(frag, "access_token="+url.QueryEscape(accessTok), "token_type=Bearer", "expires_in="+strconv.Itoa(h.accessTokenLifetime()))
			}
		}
		if strings.Contains(respType, "id_token") {
			opts := &token.IDTokenOptions{AMR: []string{"sms"}, CustomClaims: ruleUser.IDTokenClaims}
			idTok, err := h.Issuer.IssueIDToken(u.ID, aud, data.ClientID, h.idTokenLifetime(), data.Scope, emailVal, displayName, "", opts)
			if err == nil {
				frag = append(frag, "id_token="+url.QueryEscape(idTok))
			}
		}
		if state != "" {
			frag = append(frag, "state="+url.QueryEscape(state))
		}
		dest := redirectURL.String()
		if redirectURL.RawQuery != "" {
			dest = strings.TrimSuffix(dest, "?"+redirectURL.RawQuery)
		}
		http.Redirect(w, r, dest+"#"+strings.Join(frag, "&"), http.StatusFound)
		return
	}
	if h.GrantStore == nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Authorization code flow not configured"})
		return
	}
	authCode := "ac_" + uuid.New().String()
	sessionID := "sid_" + uuid.New().String()
	h.GrantStore.SaveCode(authCode, &grants.AuthCode{
		UserID:      u.ID,
		ClientID:    data.ClientID,
		RedirectURI: redirectURI,
		Scope:       data.Scope,
		Nonce:       "",
		SessionID:   sessionID,
		Audience:    aud,
	})
	q := redirectURL.Query()
	q.Set("code", authCode)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()
	audit.LogToken("sms_otp", u.ID, data.ClientID, true, nil)
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (h *Handlers) handleMagicLinkVerify(w http.ResponseWriter, r *http.Request, magicToken, queryState string) {
	data, ok := h.Store.ConsumeMagicLinkToken(r.Context(), magicToken)
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Invalid or expired magic link.</p></body></html>`))
		return
	}
	redirectURI := data.RedirectURI
	state := data.State
	if queryState != "" {
		state = queryState
	}

	// Create or get user, email_verified=true
	u, err := h.Store.GetByEmail(r.Context(), data.Email)
	if err != nil || u == nil {
		u = &store.User{
			ID:            "auth0|" + uuid.New().String(),
			Email:         data.Email,
			PasswordHash:  "", // passwordless; use placeholder
			DisplayName:   data.Email,
			EmailVerified: true,
		}
		// CreateUser requires non-empty password for bcrypt
		placeholder := "x" + uuid.New().String()
		if err := h.Store.CreateUser(r.Context(), u, placeholder); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		audit.LogSignup(u.ID, data.Email, nil)
	} else {
		if !u.EmailVerified {
			_ = h.Store.UpdateEmailVerified(r.Context(), u.ID, true)
			u.EmailVerified = true
		}
	}

	// Set session if SessionStore available
	if h.SessionStore != nil {
		if sessionID, err := h.SessionStore.Create(u.ID, u.Email); err == nil {
			cookie := &http.Cookie{
				Name:     sessionCookieName,
				Value:    sessionID,
				Path:     "/",
				MaxAge:   sessionCookieMaxAge,
				HttpOnly: true,
				Secure:   strings.HasPrefix(h.issuerURL(), "https://"),
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, cookie)
		}
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid redirect_uri"})
		return
	}

	aud := data.Audience
	if aud == "" && data.ClientID != "" {
		aud = data.ClientID
	}
	if aud == "" {
		aud = "https://api.example.com"
	}

	ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
	if h.RulesRunner != nil {
		ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: data.ClientID, Connection: "email", Protocol: "oidc-basic-profile"})
	}
	emailVal, displayName := ruleUser.Email, ruleUser.Name
	if displayName == "" {
		displayName = ruleUser.Nickname
	}
	if displayName == "" {
		displayName = emailVal
	}

	// response_type: code (auth code) or token/id_token (implicit)
	respType := data.ResponseType
	if respType == "" {
		respType = "code"
	}
	if strings.Contains(respType, "token") || strings.Contains(respType, "id_token") {
		var frag []string
		if strings.Contains(respType, "token") {
			accessTok, err := h.Issuer.Issue(u.ID, aud, data.ClientID, h.accessTokenLifetime(), ruleUser.AccessTokenClaims)
			if err == nil {
				frag = append(frag, "access_token="+url.QueryEscape(accessTok), "token_type=Bearer", "expires_in="+strconv.Itoa(h.accessTokenLifetime()))
			}
		}
		if strings.Contains(respType, "id_token") {
			opts := &token.IDTokenOptions{AMR: []string{"magiclink"}, CustomClaims: ruleUser.IDTokenClaims}
			idTok, err := h.Issuer.IssueIDToken(u.ID, aud, data.ClientID, h.idTokenLifetime(), data.Scope, emailVal, displayName, "", opts)
			if err == nil {
				frag = append(frag, "id_token="+url.QueryEscape(idTok))
			}
		}
		if state != "" {
			frag = append(frag, "state="+url.QueryEscape(state))
		}
		dest := redirectURL.String()
		if redirectURL.RawQuery != "" {
			dest = strings.TrimSuffix(dest, "?"+redirectURL.RawQuery)
		}
		http.Redirect(w, r, dest+"#"+strings.Join(frag, "&"), http.StatusFound)
		return
	}

	// Auth code flow
	if h.GrantStore == nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Authorization code flow not configured"})
		return
	}
	authCode := "ac_" + uuid.New().String()
	sessionID := "sid_" + uuid.New().String()
	h.GrantStore.SaveCode(authCode, &grants.AuthCode{
		UserID:      u.ID,
		ClientID:    data.ClientID,
		RedirectURI: redirectURI,
		Scope:       data.Scope,
		Nonce:       "",
		SessionID:   sessionID,
		Audience:    aud,
	})
	q := redirectURL.Query()
	q.Set("code", authCode)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()
	audit.LogToken("magiclink", u.ID, data.ClientID, true, nil)
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (h *Handlers) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var token, newPassword string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			Token       string `json:"token"`
			NewPassword string `json:"new_password"`
		}
		if json.NewDecoder(r.Body).Decode(&req) == nil {
			token = req.Token
			newPassword = req.NewPassword
		}
	} else {
		_ = r.ParseForm()
		token = r.FormValue("token")
		newPassword = r.FormValue("new_password")
	}
	if token == "" || newPassword == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "token and new_password required"})
		return
	}
	if err := password.Validate(newPassword); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_password", "error_description": err.Error()})
		return
	}
	if password.IsBreachedCheckEnabled() {
		if err := password.IsBreached(newPassword); err != nil {
			if err == password.ErrBreached {
				sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_password", "error_description": "This password has been found in a data breach and cannot be used. Please choose a different password."})
				return
			}
			sendJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "server_error", "error_description": "Unable to verify password. Please try again later."})
			return
		}
	}
	userID, ok := h.Store.ConsumePasswordResetToken(r.Context(), token)
	if !ok {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid or expired reset token"})
		return
	}
	if err := h.Store.UpdatePassword(r.Context(), userID, newPassword); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"message": "Password has been reset."})
}

func (h *Handlers) handleGetUser(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(path, "/")
	id := parts[len(parts)-1]
	setRateLimitHeaders(w)
	u, err := h.Store.GetByID(r.Context(), id)
	if err != nil || u == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found", "message": "The user does not exist."})
		return
	}
	out := userToAuth0Response(u)
	sendJSON(w, http.StatusOK, out)
}

func userToAuth0Response(u *store.User) map[string]interface{} {
	out := map[string]interface{}{
		"user_id":        u.ID,
		"email":          u.Email,
		"email_verified": u.EmailVerified,
		"name":           u.DisplayName,
		"nickname":       u.DisplayName,
	}
	if u.UserMetadata != nil {
		out["user_metadata"] = u.UserMetadata
	}
	if u.AppMetadata != nil {
		out["app_metadata"] = u.AppMetadata
	}
	return out
}

func (h *Handlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	q := r.URL.Query().Get("q")
	includeTotals := r.URL.Query().Get("include_totals") == "true"

	users, total, err := h.Store.ListUsers(r.Context(), store.ListUsersOpts{Page: page, PerPage: perPage, Query: q})
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for i := range users {
		out = append(out, userToAuth0Response(&users[i]))
	}
	if includeTotals {
		sendJSON(w, http.StatusOK, map[string]interface{}{
			"start": page * perPage,
			"limit": perPage,
			"total": total,
			"users": out,
		})
	} else {
		sendJSON(w, http.StatusOK, out)
	}
}

func (h *Handlers) handleUsersExport(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage <= 0 {
		perPage = 100
	}
	if perPage > 100 {
		perPage = 100
	}

	users, _, err := h.Store.ListUsersExport(r.Context(), page, perPage)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusOK, users)
}

func (h *Handlers) handleUsersImport(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	var req []struct {
		Email         string                 `json:"email"`
		Password      string                 `json:"password"`
		Name          string                 `json:"name"`
		EmailVerified bool                   `json:"email_verified"`
		UserMetadata  map[string]interface{} `json:"user_metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "message": "Invalid JSON array"})
		return
	}

	var created int
	var failed []map[string]interface{}
	for i, u := range req {
		if u.Email == "" {
			failed = append(failed, map[string]interface{}{"index": i, "email": u.Email, "error": "email required"})
			continue
		}
		pwd := u.Password
		if pwd == "" {
			pwd = "password123"
		}
		if err := password.Validate(pwd); err != nil {
			failed = append(failed, map[string]interface{}{"index": i, "email": u.Email, "error": err.Error()})
			continue
		}
		uid := "auth0|" + uuid.New().String()
		displayName := u.Name
		if displayName == "" {
			displayName = u.Email
			if idx := strings.Index(u.Email, "@"); idx > 0 {
				displayName = u.Email[:idx]
			}
		}
		user := &store.User{
			ID:             uid,
			Email:          u.Email,
			DisplayName:    displayName,
			EmailVerified:  u.EmailVerified,
			OrganizationID: 1,
			EnterpriseID:   1,
			Role:           "user",
			UserMetadata:   u.UserMetadata,
		}
		if err := h.Store.CreateUser(r.Context(), user, pwd); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate") {
				failed = append(failed, map[string]interface{}{"index": i, "email": u.Email, "error": "user already exists"})
			} else {
				failed = append(failed, map[string]interface{}{"index": i, "email": u.Email, "error": err.Error()})
			}
			continue
		}
		created++
	}

	sendJSON(w, http.StatusOK, map[string]interface{}{
		"created": created,
		"failed":  failed,
	})
}

func (h *Handlers) handleUserGDPRExport(w http.ResponseWriter, r *http.Request, path string) {
	userID := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v2/users/"), "/export")
	if userID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)

	u, err := h.Store.GetByID(r.Context(), userID)
	if err != nil || u == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found", "message": "The user does not exist."})
		return
	}

	roles, _ := h.Store.GetUserRoles(r.Context(), userID)
	blocked, _ := h.Store.IsUserBlocked(r.Context(), userID)

	roleNames := make([]string, 0, len(roles))
	for _, ro := range roles {
		roleNames = append(roleNames, ro.Name)
	}

	out := map[string]interface{}{
		"user_id":        u.ID,
		"email":          u.Email,
		"name":           u.DisplayName,
		"email_verified":  u.EmailVerified,
		"user_metadata":  u.UserMetadata,
		"app_metadata":   u.AppMetadata,
		"roles":          roleNames,
		"blocked":        blocked,
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleCreateUserMgmt(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	var req struct {
		Connection   string                 `json:"connection"`
		Email       string                 `json:"email"`
		Password    string                 `json:"password"`
		Name        string                 `json:"name"`
		UserMetadata map[string]interface{} `json:"user_metadata"`
		AppMetadata  map[string]interface{} `json:"app_metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "message": "Invalid JSON"})
		return
	}
	if req.Email == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "message": "Email is required"})
		return
	}
	if req.Password == "" {
		req.Password = "password123"
	}
	if err := password.Validate(req.Password); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_password", "message": err.Error()})
		return
	}
	uid := "auth0|" + uuid.New().String()
	displayName := req.Name
	if displayName == "" {
		displayName = req.Email
		if i := strings.Index(req.Email, "@"); i > 0 {
			displayName = req.Email[:i]
		}
	}
	emailVerified := handlersEmailVerificationRequired() == false
	u := &store.User{
		ID:             uid,
		Email:          req.Email,
		DisplayName:    displayName,
		EmailVerified:  emailVerified,
		OrganizationID: 1,
		EnterpriseID:   1,
		Role:           "user",
		UserMetadata:   req.UserMetadata,
		AppMetadata:    req.AppMetadata,
	}
	if err := h.Store.CreateUser(r.Context(), u, req.Password); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate") {
			sendJSON(w, http.StatusConflict, map[string]string{"error": "Conflict", "message": "The user already exists."})
			return
		}
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusCreated, userToAuth0Response(u))
}

func (h *Handlers) handleDeleteUser(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(path, "/")
	id := parts[len(parts)-1]
	setRateLimitHeaders(w)
	if err := h.Store.DeleteUser(r.Context(), id); err != nil {
		audit.LogUserChange("delete", id, false, map[string]interface{}{"error": err.Error()})
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	audit.LogUserChange("delete", id, true, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	id := parts[len(parts)-1]
	setRateLimitHeaders(w)
	u, err := h.Store.GetByID(r.Context(), id)
	if err != nil || u == nil {
		audit.LogUserChange("patch", id, false, map[string]interface{}{"reason": "not_found"})
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found", "message": "The user does not exist."})
		return
	}
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		audit.LogUserChange("patch", id, false, map[string]interface{}{"reason": "invalid_json"})
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "message": "Invalid JSON"})
		return
	}
	if err := h.Store.UpdateUser(r.Context(), id, updates); err != nil {
		audit.LogUserChange("patch", id, false, map[string]interface{}{"error": err.Error()})
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	audit.LogUserChange("patch", id, true, nil)
	updated, _ := h.Store.GetByID(r.Context(), id)
	sendJSON(w, http.StatusOK, userToAuth0Response(updated))
}

func extractIDFromPath(path, prefix string) string {
	path = strings.TrimSuffix(path, "/")
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	return strings.TrimPrefix(path, prefix)
}

func (h *Handlers) handleGetUserBlocks(w http.ResponseWriter, r *http.Request, path string) {
	userID := extractIDFromPath(path, "/api/v2/users/")
	userID = strings.TrimSuffix(userID, "/blocks")
	if userID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	blocked, err := h.Store.IsUserBlocked(r.Context(), userID)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := []map[string]interface{}{}
	if blocked {
		out = append(out, map[string]interface{}{"blocked_for": []interface{}{}, "identifier": userID})
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleUserBlocksModify(w http.ResponseWriter, r *http.Request, path string) {
	userID := extractIDFromPath(path, "/api/v2/users/")
	userID = strings.TrimSuffix(userID, "/blocks")
	if userID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	if r.Method == http.MethodPost {
		if err := h.Store.BlockUser(r.Context(), userID); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
	} else {
		if err := h.Store.UnblockUser(r.Context(), userID); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "message": "Invalid JSON"})
		return
	}
	if req.Name == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "message": "Name is required"})
		return
	}
	roleID := "rol_" + uuid.New().String()[:8]
	ro := &store.Role{ID: roleID, Name: req.Name, Description: req.Description}
	if err := h.Store.CreateRole(r.Context(), ro); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			sendJSON(w, http.StatusConflict, map[string]string{"error": "Conflict", "message": "Role already exists"})
			return
		}
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusCreated, map[string]interface{}{"id": ro.ID, "name": ro.Name, "description": ro.Description})
}

func (h *Handlers) handleGetRole(w http.ResponseWriter, r *http.Request, path string) {
	id := extractIDFromPath(path, "/api/v2/roles/")
	if id == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	ro, err := h.Store.GetRoleByID(r.Context(), id)
	if err != nil || ro == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found", "message": "The role does not exist."})
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{"id": ro.ID, "name": ro.Name, "description": ro.Description})
}

func (h *Handlers) handlePatchRole(w http.ResponseWriter, r *http.Request, path string) {
	id := extractIDFromPath(path, "/api/v2/roles/")
	if id == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "message": "Invalid JSON"})
		return
	}
	ro, _ := h.Store.GetRoleByID(r.Context(), id)
	if ro == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found", "message": "The role does not exist."})
		return
	}
	name, desc := ro.Name, ro.Description
	if req.Name != "" {
		name = req.Name
	}
	if req.Description != "" {
		desc = req.Description
	}
	if err := h.Store.UpdateRole(r.Context(), id, name, desc); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{"id": id, "name": name, "description": desc})
}

func (h *Handlers) handleDeleteRole(w http.ResponseWriter, r *http.Request, path string) {
	id := extractIDFromPath(path, "/api/v2/roles/")
	if id == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	if err := h.Store.DeleteRole(r.Context(), id); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleListClients(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	clients, err := h.Store.ListClients(r.Context())
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for _, c := range clients {
		out = append(out, clientToAuth0Response(&c))
	}
	sendJSON(w, http.StatusOK, out)
}

func clientToAuth0Response(c *store.Client) map[string]interface{} {
	out := map[string]interface{}{
		"client_id":       c.ID,
		"name":            c.Name,
		"app_type":        c.AppType,
		"callbacks":       c.Callbacks,
		"allowed_origins": c.AllowedOrigins,
	}
	return out
}

func (h *Handlers) handleGetClient(w http.ResponseWriter, r *http.Request, path string) {
	id := extractIDFromPath(path, "/api/v2/clients/")
	if id == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	c, err := h.Store.GetClientByID(r.Context(), id)
	if err != nil || c == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found", "message": "The client does not exist."})
		return
	}
	sendJSON(w, http.StatusOK, clientToAuth0Response(c))
}

func (h *Handlers) handlePatchClient(w http.ResponseWriter, r *http.Request, path string) {
	id := extractIDFromPath(path, "/api/v2/clients/")
	if id == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	c, _ := h.Store.GetClientByID(r.Context(), id)
	if c == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found", "message": "The client does not exist."})
		return
	}
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "message": "Invalid JSON"})
		return
	}
	// Convert arrays from JSON
	if v, ok := updates["callbacks"].([]interface{}); ok {
		var arr []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				arr = append(arr, s)
			}
		}
		updates["callbacks"] = arr
	}
	if v, ok := updates["allowed_origins"].([]interface{}); ok {
		var arr []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				arr = append(arr, s)
			}
		}
		updates["allowed_origins"] = arr
	}
	if err := h.Store.UpdateClient(r.Context(), id, updates); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	updated, _ := h.Store.GetClientByID(r.Context(), id)
	sendJSON(w, http.StatusOK, clientToAuth0Response(updated))
}

func (h *Handlers) handleListConnections(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	conns, err := h.Store.ListConnections(r.Context())
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for _, c := range conns {
		out = append(out, map[string]interface{}{
			"id":       c.ID,
			"name":     c.Name,
			"strategy": c.Strategy,
		})
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleGetConnection(w http.ResponseWriter, r *http.Request, path string) {
	id := extractIDFromPath(path, "/api/v2/connections/")
	if id == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	c, err := h.Store.GetConnectionByID(r.Context(), id)
	if err != nil || c == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found", "message": "The connection does not exist."})
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"id":       c.ID,
		"name":     c.Name,
		"strategy": c.Strategy,
	})
}

func (h *Handlers) handleListLogs(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	limit, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	logs, err := h.Store.ListLogs(r.Context(), limit)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for _, l := range logs {
		out = append(out, map[string]interface{}{
			"log_id":   l.ID,
			"type":     l.EventType,
			"user_id":  l.UserID,
			"client_id": l.ClientID,
			"date":     l.Payload,
		})
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleJWKS(w http.ResponseWriter) {
	b, err := h.Issuer.JWKS()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (h *Handlers) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "Missing or invalid Authorization header"})
		return
	}
	tokStr := strings.TrimPrefix(auth, "Bearer ")
	claims, err := h.Issuer.Validate(tokStr)
	if err != nil {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": err.Error()})
		return
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "Missing sub claim"})
		return
	}
	u, err := h.Store.GetByID(r.Context(), sub)
	if err != nil || u == nil {
		profile := map[string]interface{}{"sub": sub}
		if email, ok := claims["email"].(string); ok {
			profile["email"] = email
			profile["email_verified"] = true
		}
		if name, ok := claims["name"].(string); ok {
			profile["name"] = name
		}
		sendJSON(w, http.StatusOK, profile)
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"sub":             u.ID,
		"email":           u.Email,
		"email_verified":  u.EmailVerified,
		"name":            u.DisplayName,
	})
}

func (h *Handlers) handleTokeninfo(w http.ResponseWriter, r *http.Request) {
	var tokenStr string
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var params map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&params); err == nil {
			tokenStr, _ = params["id_token"].(string)
			if tokenStr == "" {
				tokenStr, _ = params["access_token"].(string)
			}
		}
	} else {
		_ = r.ParseForm()
		tokenStr = r.FormValue("id_token")
		if tokenStr == "" {
			tokenStr = r.FormValue("access_token")
		}
	}
	if tokenStr == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "id_token or access_token required"})
		return
	}
	claims, err := h.Issuer.Validate(tokenStr)
	if err != nil {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": err.Error()})
		return
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "Missing sub claim"})
		return
	}
	u, err := h.Store.GetByID(r.Context(), sub)
	if err != nil || u == nil {
		profile := map[string]interface{}{
			"user_id": sub,
			"sub":     sub,
		}
		for k, v := range claims {
			profile[k] = v
		}
		sendJSON(w, http.StatusOK, profile)
		return
	}
	profile := map[string]interface{}{
		"user_id":        u.ID,
		"sub":            u.ID,
		"email":          u.Email,
		"email_verified": u.EmailVerified,
		"name":           u.DisplayName,
	}
	for k, v := range claims {
		if _, has := profile[k]; !has {
			profile[k] = v
		}
	}
	sendJSON(w, http.StatusOK, profile)
}

func (h *Handlers) handleOpenIDConfig(w http.ResponseWriter) {
	base := h.issuerURL()
	cfg := map[string]interface{}{
		"issuer":                    base + "/",
		"jwks_uri":                  base + "/.well-known/jwks.json",
		"token_endpoint":            base + "/oauth/token",
		"authorization_endpoint":    base + "/authorize",
		"userinfo_endpoint":         base + "/userinfo",
		"end_session_endpoint":      base + "/v2/logout",
		"revocation_endpoint":       base + "/oauth/revoke",
		"introspection_endpoint":    base + "/oauth/introspect",
	}
	sendJSON(w, http.StatusOK, cfg)
}

func sendJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func handlersEmailVerificationRequired() bool {
	return os.Getenv("EMAIL_VERIFICATION_REQUIRED") != "false"
}

func toInt(v interface{}) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	default:
		return 0, false
	}
}

func (h *Handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	if h.SessionStore != nil {
		if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			h.SessionStore.Revoke(c.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	returnTo := r.URL.Query().Get("returnTo")
	if returnTo == "" {
		returnTo = r.URL.Query().Get("post_logout_redirect_uri")
	}
	state := r.URL.Query().Get("state")
	if returnTo != "" {
		dest, err := url.Parse(returnTo)
		if err == nil {
			q := dest.Query()
			if state != "" {
				q.Set("state", state)
			}
			dest.RawQuery = q.Encode()
			http.Redirect(w, r, dest.String(), http.StatusFound)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(`<!DOCTYPE html><html><body><p>You have been logged out.</p></body></html>`))
}

func (h *Handlers) handleUniversalLogin(w http.ResponseWriter, r *http.Request) {
	h.handleLogin(w, r)
}

func (h *Handlers) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "state required", http.StatusBadRequest)
		return
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	clientID := r.URL.Query().Get("client_id")
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "openid"
	}
	if redirectURI != "" && clientID != "" {
		loginURL := h.issuerURL() + "/login?client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&scope=" + url.QueryEscape(scope) + "&state=" + url.QueryEscape(state)
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	http.Error(w, "redirect_uri and client_id required", http.StatusBadRequest)
}

func (h *Handlers) handleSocialCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	connection := r.URL.Query().Get("connection")
	if state == "" || code == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>state and code are required.</p></body></html>`))
		return
	}
	if h.GrantStore == nil {
		http.Error(w, "Social login not configured", http.StatusInternalServerError)
		return
	}
	ss, ok := h.GrantStore.ConsumeSocialState(state)
	if !ok || ss == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Invalid or expired state. Please try again.</p></body></html>`))
		return
	}
	// Use connection from state if not in query (provider may not echo it)
	if connection == "" {
		connection = ss.Connection
	}
	prov := social.GetProvider(connection)
	if prov == nil {
		redirectWithError(w, r, ss.RedirectURI, ss.State, "invalid_connection", "Unknown connection")
		return
	}
	callbackURL := strings.TrimSuffix(h.issuerURL(), "/") + "/callback/social"
	userInfo, err := prov.ExchangeCode(r.Context(), code, callbackURL)
	if err != nil {
		redirectWithError(w, r, ss.RedirectURI, ss.State, "server_error", "Failed to exchange code")
		return
	}
	if userInfo.Email == "" {
		redirectWithError(w, r, ss.RedirectURI, ss.State, "server_error", "Provider did not return email")
		return
	}
	// Resolve to local user: by provider identity, then by email
	u, err := h.Store.GetUserByProviderIdentity(r.Context(), connection, userInfo.Sub)
	if err != nil {
		redirectWithError(w, r, ss.RedirectURI, ss.State, "server_error", "Database error")
		return
	}
	if u == nil {
		u, err = h.Store.GetByEmail(r.Context(), userInfo.Email)
		if err != nil {
			redirectWithError(w, r, ss.RedirectURI, ss.State, "server_error", "Database error")
			return
		}
		if u != nil {
			_ = h.Store.LinkUserIdentity(r.Context(), u.ID, connection, userInfo.Sub)
		}
	}
	if u == nil {
		// Create new user (email_verified=true from social)
		uid := "auth0|" + uuid.New().String()
		displayName := userInfo.Name
		if displayName == "" {
			displayName = userInfo.Email
			if i := strings.Index(userInfo.Email, "@"); i > 0 {
				displayName = userInfo.Email[:i]
			}
		}
		// Random password - social users don't use it
		socialPass := "soc_" + uuid.New().String() + uuid.New().String()[:8]
		u = &store.User{
			ID:             uid,
			Email:          userInfo.Email,
			DisplayName:    displayName,
			EmailVerified:  true,
			OrganizationID:  1,
			EnterpriseID:   1,
			Role:           "user",
			AppMetadata:    map[string]interface{}{"providers": []map[string]string{{"provider": connection, "user_id": userInfo.Sub}}},
		}
		if err := h.Store.CreateUser(r.Context(), u, socialPass); err != nil {
			redirectWithError(w, r, ss.RedirectURI, ss.State, "server_error", "Failed to create user")
			return
		}
		_ = h.Store.LinkUserIdentity(r.Context(), u.ID, connection, userInfo.Sub)
	}
	// Set session
	if h.SessionStore != nil {
		if sid, err := h.SessionStore.Create(u.ID, u.Email); err == nil {
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    sid,
				Path:     "/",
				MaxAge:   sessionCookieMaxAge,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}
	}
	// Redirect to original redirect_uri with code (auth code flow) or token (implicit)
	redirectURL, _ := url.Parse(ss.RedirectURI)
	if ss.ResponseType == "token" || strings.Contains(ss.ResponseType, "token") || strings.Contains(ss.ResponseType, "id_token") {
		// Implicit flow
		aud := ss.Audience
		if aud == "" {
			aud = ss.ClientID
		}
		if aud == "" {
			aud = "https://api.example.com"
		}
		ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
		if h.RulesRunner != nil {
			ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: ss.ClientID, Connection: connection, Protocol: "oidc-basic-profile"})
		}
		email, displayName := ruleUser.Email, ruleUser.Name
		if displayName == "" {
			displayName = ruleUser.Nickname
		}
		if displayName == "" {
			displayName = email
		}
		var frag []string
		if strings.Contains(ss.ResponseType, "token") {
			accessTok, err := h.Issuer.Issue(u.ID, aud, ss.ClientID, h.accessTokenLifetime(), ruleUser.AccessTokenClaims)
			if err == nil {
				frag = append(frag, "access_token="+url.QueryEscape(accessTok), "token_type=Bearer", "expires_in="+strconv.Itoa(h.accessTokenLifetime()))
			}
		}
		if strings.Contains(ss.ResponseType, "id_token") {
			opts := &token.IDTokenOptions{AMR: []string{"oidc"}, CustomClaims: ruleUser.IDTokenClaims}
			idTok, err := h.Issuer.IssueIDToken(u.ID, aud, ss.ClientID, h.idTokenLifetime(), ss.Scope, email, displayName, "", opts)
			if err == nil {
				frag = append(frag, "id_token="+url.QueryEscape(idTok))
			}
		}
		if ss.State != "" {
			frag = append(frag, "state="+url.QueryEscape(ss.State))
		}
		dest := redirectURL.String()
		if redirectURL.RawQuery != "" {
			dest = strings.TrimSuffix(dest, "?"+redirectURL.RawQuery)
		}
		http.Redirect(w, r, dest+"#"+strings.Join(frag, "&"), http.StatusFound)
		return
	}
	// Auth code flow
	authCode := "ac_" + uuid.New().String()
	sessionID := "sid_" + uuid.New().String()
	h.GrantStore.SaveCode(authCode, &grants.AuthCode{
		UserID:              u.ID,
		ClientID:            ss.ClientID,
		RedirectURI:         ss.RedirectURI,
		Scope:               ss.Scope,
		Nonce:               ss.Nonce,
		SessionID:           sessionID,
		Audience:            ss.Audience,
		CodeChallenge:       ss.CodeChallenge,
		CodeChallengeMethod: ss.CodeChallengeMethod,
	})
	q := redirectURL.Query()
	q.Set("code", authCode)
	if ss.State != "" {
		q.Set("state", ss.State)
	}
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	dest, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, errDesc, http.StatusInternalServerError)
		return
	}
	q := dest.Query()
	q.Set("error", errCode)
	q.Set("error_description", errDesc)
	if state != "" {
		q.Set("state", state)
	}
	dest.RawQuery = q.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func extractUserIDFromPath(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	parts := strings.Split(path, "/")
	if len(parts) >= 4 {
		return parts[4]
	}
	return ""
}

func (h *Handlers) handleGetUserRoles(w http.ResponseWriter, r *http.Request, path string) {
	userID := extractUserIDFromPath(path, "/roles")
	if userID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	roles, err := h.Store.GetUserRoles(r.Context(), userID)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for _, ro := range roles {
		out = append(out, map[string]interface{}{"id": ro.ID, "name": ro.Name, "description": ro.Description})
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleGetUserPermissions(w http.ResponseWriter, r *http.Request, path string) {
	userID := extractUserIDFromPath(path, "/permissions")
	if userID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	perms, err := h.Store.GetUserPermissions(r.Context(), userID)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for _, p := range perms {
		out = append(out, map[string]interface{}{
			"permission_name":               p.Name,
			"resource_server_identifier":    p.ResourceServerIdentifier,
			"resource_server_name":          p.ResourceServerIdentifier,
			"description":                   p.Description,
		})
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleListRoles(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	roles, err := h.Store.ListRoles(r.Context())
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for _, ro := range roles {
		out = append(out, map[string]interface{}{"id": ro.ID, "name": ro.Name, "description": ro.Description})
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleUserRolesModify(w http.ResponseWriter, r *http.Request, path string) {
	userID := extractUserIDFromPath(path, "/roles")
	if userID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	var raw map[string]interface{}
	if json.NewDecoder(r.Body).Decode(&raw) != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rolesVal, _ := raw["roles"].([]interface{})
	for _, rv := range rolesVal {
		var roleID string
		switch v := rv.(type) {
		case string:
			roleID = v
		case map[string]interface{}:
			if id, ok := v["id"].(string); ok {
				roleID = id
			}
		}
		if roleID != "" {
			if r.Method == http.MethodDelete {
				h.Store.RemoveRoleFromUser(r.Context(), userID, roleID)
			} else {
				h.Store.AssignRoleToUser(r.Context(), userID, roleID)
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
