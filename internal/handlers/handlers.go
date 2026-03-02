package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/radimal/fake-auth0/internal/store"
	"github.com/radimal/fake-auth0/internal/token"
)

type Handlers struct {
	Store     *store.SQLiteStore
	Issuer    *token.Issuer
	IssuerURL string
}

func (h *Handlers) issuerURL() string {
	if h.IssuerURL != "" {
		return strings.TrimSuffix(h.IssuerURL, "/")
	}
	return "https://fake-auth0.example.com"
}

func corsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PATCH")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func setRateLimitHeaders(w http.ResponseWriter) {
	w.Header().Set("x-ratelimit-limit", "1000")
	w.Header().Set("x-ratelimit-remaining", "999")
	w.Header().Set("x-ratelimit-reset", "9999999999")
}

func (h *Handlers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodPost && path == "/oauth/token":
		h.handleToken(w, r)
	case r.Method == http.MethodPost && path == "/dbconnections/signup":
		h.handleSignup(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v2/users/") && !strings.Contains(path, "/roles"):
		h.handleGetUser(w, r, path)
	case (r.Method == http.MethodDelete || r.Method == http.MethodPost) && strings.Contains(path, "/api/v2/users/") && strings.HasSuffix(path, "/roles"):
		setRateLimitHeaders(w)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v2/users/") && !strings.Contains(path, "/roles"):
		h.handlePatchUser(w, r)
	case r.Method == http.MethodGet && path == "/.well-known/jwks.json":
		h.handleJWKS(w)
	case r.Method == http.MethodGet && path == "/.well-known/openid-configuration":
		h.handleOpenIDConfig(w)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handlers) handleToken(w http.ResponseWriter, r *http.Request) {
	var grantType, username, password, clientID string
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var params map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&params); err == nil {
			grantType, _ = params["grant_type"].(string)
			username, _ = params["username"].(string)
			password, _ = params["password"].(string)
			clientID, _ = params["client_id"].(string)
		}
	} else {
		_ = r.ParseForm()
		grantType = r.FormValue("grant_type")
		username = r.FormValue("username")
		password = r.FormValue("password")
		clientID = r.FormValue("client_id")
	}
	if clientID == "" {
		clientID = "radimal-e2e"
	}
	switch grantType {
	case "client_credentials":
		h.handleClientCredentials(w, r, clientID)
		return
	case "http://auth0.com/oauth/grant-type/password-realm", "password":
		h.handlePasswordGrant(w, r, username, password, clientID)
		return
	default:
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (h *Handlers) handlePasswordGrant(w http.ResponseWriter, r *http.Request, username, password, clientID string) {
	if username == "" || password == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Wrong email or password."})
		return
	}
	u, err := h.Store.GetByEmail(r.Context(), username)
	if err != nil || u == nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Wrong email or password."})
		return
	}
	if !h.Store.VerifyPassword(u.PasswordHash, password) {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Wrong email or password."})
		return
	}
	aud := "https://vet.radimal.ai"
	if clientID != "" {
		aud = clientID
	}
	tok, err := h.Issuer.Issue(u.ID, aud, clientID, 86400)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   86400,
	})
}

func (h *Handlers) handleClientCredentials(w http.ResponseWriter, r *http.Request, clientID string) {
	tok, err := h.Issuer.Issue("client|"+clientID, "https://api.radimal.ai", clientID, 86400)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   86400,
	})
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
	u := &store.User{
		ID:             uid,
		Email:          req.Email,
		DisplayName:    displayName,
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
	sendJSON(w, http.StatusCreated, map[string]string{"email": req.Email, "_id": u.ID})
}

func (h *Handlers) handleGetUser(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(path, "/")
	id := parts[len(parts)-1]
	setRateLimitHeaders(w)
	u, err := h.Store.GetByID(r.Context(), id)
	if err != nil || u == nil {
		sendJSON(w, http.StatusOK, map[string]string{"user_id": id})
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"user_id": u.ID,
		"email":   u.Email,
	})
}

func (h *Handlers) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	id := parts[len(parts)-1]
	_ = id
	setRateLimitHeaders(w)
	sendJSON(w, http.StatusOK, map[string]interface{}{})
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

func (h *Handlers) handleOpenIDConfig(w http.ResponseWriter) {
	base := h.issuerURL()
	cfg := map[string]interface{}{
		"issuer":                 base + "/",
		"jwks_uri":               base + "/.well-known/jwks.json",
		"token_endpoint":         base + "/oauth/token",
		"authorization_endpoint":  base + "/authorize",
	}
	sendJSON(w, http.StatusOK, cfg)
}

func sendJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
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
