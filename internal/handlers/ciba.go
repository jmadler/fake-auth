package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmadler/auth2/internal/rules"
	"github.com/jmadler/auth2/internal/store"
	"github.com/jmadler/auth2/internal/token"
)

const cibaGrantType = "urn:openid:params:grant-type:ciba"
const cibaExpiresIn = 300 // 5 minutes
const cibaInterval = 2    // poll interval in seconds

func (h *Handlers) handleCIBARequest(w http.ResponseWriter, r *http.Request) {
	p := h.parseTokenParams(r)
	clientID := p["client_id"]
	loginHint := p["login_hint"]
	scope := p["scope"]
	if clientID == "" {
		clientID = "e2e-test"
	}
	if loginHint == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "login_hint is required"})
		return
	}
	if scope == "" {
		scope = "openid"
	}
	authReqID := "ciba_" + uuid.New().String()
	expiresAt := time.Now().Add(time.Duration(cibaExpiresIn) * time.Second)
	req := &store.CIBARequest{
		AuthReqID: authReqID,
		ClientID:  clientID,
		LoginHint: loginHint,
		Scope:     scope,
		Audience:  p["audience"],
		Status:    "pending",
		ExpiresAt: expiresAt,
	}
	if err := h.Store.SaveCIBARequest(r.Context(), req); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	base := h.issuerURL()
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"auth_req_id": authReqID,
		"expires_in":  cibaExpiresIn,
		"interval":    cibaInterval,
		"verification_uri":         base + "/ciba/verify",
		"verification_uri_complete": base + "/ciba/verify?auth_req_id=" + authReqID,
	})
}

func (h *Handlers) handleCIBAVerify(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_req_id")
	if authReqID == "" {
		authReqID = r.FormValue("auth_req_id")
	}
	if authReqID == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>auth_req_id is required</p></body></html>`))
		return
	}
	req, err := h.Store.GetCIBARequest(r.Context(), authReqID)
	if err != nil || req == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Invalid or expired auth request</p></body></html>`))
		return
	}
	if req.Status != "pending" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><body><p>This request has already been completed.</p></body></html>`))
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		action := r.FormValue("action")
		username := r.FormValue("username")
		password := r.FormValue("password")
		if action == "deny" {
			_ = h.Store.UpdateCIBARequestStatus(r.Context(), authReqID, "denied", "")
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
			w.Write([]byte(`<!DOCTYPE html><html><body><p>Invalid credentials.</p><a href="?auth_req_id=` + authReqID + `">Try again</a></body></html>`))
			return
		}
		// Validate login_hint matches user (email or user_id)
		if req.LoginHint != u.Email && req.LoginHint != u.ID {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<!DOCTYPE html><html><body><p>This request is for a different user.</p></body></html>`))
			return
		}
		if err := h.Store.UpdateCIBARequestStatus(r.Context(), authReqID, "approved", u.ID); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Authentication approved. You can close this page.</p></body></html>`))
		return
	}
	html := `<!DOCTYPE html><html><head><title>CIBA Verify</title></head><body>
<p>Authentication request for: ` + req.LoginHint + `</p>
<form method="post" action="?auth_req_id=` + authReqID + `">
<input type="hidden" name="auth_req_id" value="` + authReqID + `">
<label>Email: <input type="text" name="username"></label><br>
<label>Password: <input type="password" name="password"></label><br>
<button type="submit" name="action" value="allow">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (h *Handlers) handleCIBAToken(w http.ResponseWriter, r *http.Request, authReqID, clientID string) {
	if authReqID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "auth_req_id is required"})
		return
	}
	req, err := h.Store.GetCIBARequest(r.Context(), authReqID)
	if err != nil || req == nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid or expired auth_req_id"})
		return
	}
	if req.ClientID != clientID && clientID != "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Client ID mismatch"})
		return
	}
	if req.Status == "denied" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "access_denied", "error_description": "User denied the request"})
		return
	}
	if req.Status != "approved" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "authorization_pending", "error_description": "User has not yet completed authorization"})
		return
	}
	// Consume: update status to consumed so we don't issue twice (optional - for simplicity we don't delete)
	// For production you'd want to mark consumed or delete
	u, err := h.Store.GetByID(r.Context(), req.UserID)
	if err != nil || u == nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	aud := req.Audience
	if aud == "" && req.ClientID != "" {
		aud = req.ClientID
	}
	if aud == "" {
		aud = "https://api.example.com"
	}
	ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
	if h.RulesRunner != nil {
		ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: req.ClientID, Connection: "Username-Password-Authentication", Protocol: "oidc-basic-profile"})
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
	accessTok, err := h.Issuer.Issue(req.UserID, aud, req.ClientID, accessLifetime, ruleUser.AccessTokenClaims)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	resp := map[string]interface{}{
		"access_token": accessTok,
		"token_type":   "Bearer",
		"expires_in":   accessLifetime,
	}
	if strings.Contains(req.Scope, "openid") {
		opts := &token.IDTokenOptions{AMR: []string{"pwd"}, SessionID: sessionID, CustomClaims: ruleUser.IDTokenClaims}
		idTok, err := h.Issuer.IssueIDToken(req.UserID, aud, req.ClientID, idLifetime, req.Scope, email, displayName, "", opts)
		if err == nil {
			resp["id_token"] = idTok
		}
	}
	// Mark as consumed so it can't be reused
	_ = h.Store.UpdateCIBARequestStatus(r.Context(), authReqID, "consumed", req.UserID)
	sendJSON(w, http.StatusOK, resp)
}
