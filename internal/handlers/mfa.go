package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jmadler/auth2/internal/audit"
	"github.com/jmadler/auth2/internal/grants"
	"github.com/jmadler/auth2/internal/mfa"
	"github.com/jmadler/auth2/internal/metrics"
	"github.com/jmadler/auth2/internal/rules"
	"github.com/jmadler/auth2/internal/token"
)

func (h *Handlers) handleMFAEnroll(w http.ResponseWriter, r *http.Request) {
	if !h.MFAEnabled {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "mfa_not_available"})
		return
	}
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "Valid access token required"})
		return
	}
	claims, err := h.Issuer.Validate(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": err.Error()})
		return
	}
	userID, _ := claims["sub"].(string)
	if userID == "" {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "Missing sub claim"})
		return
	}
	u, err := h.Store.GetByID(r.Context(), userID)
	if err != nil || u == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}
	existing, _ := h.Store.GetMFAEnrollment(r.Context(), userID)
	if existing != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "already_enrolled", "error_description": "MFA already enrolled"})
		return
	}
	secret, key, err := mfa.GenerateSecret(u.Email)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"secret":   secret,
		"qr_uri":   key.URL(),
		"user_id":  userID,
	})
}

func (h *Handlers) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	if !h.MFAEnabled {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "mfa_not_available"})
		return
	}
	// Verify requires auth and user_id must match the authenticated user
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "Valid access token required"})
		return
	}
	claims, err := h.Issuer.Validate(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": err.Error()})
		return
	}
	authUserID, _ := claims["sub"].(string)
	if authUserID == "" {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "Missing sub claim"})
		return
	}
	var req struct {
		UserID string `json:"user_id"`
		Code   string `json:"code"`
		Secret string `json:"secret"`
	}
	if err := decodeJSON(r, &req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid JSON"})
		return
	}
	if req.UserID == "" || req.Code == "" || req.Secret == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "user_id, code and secret required"})
		return
	}
	if req.UserID != authUserID {
		sendJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden", "error_description": "user_id must match authenticated user"})
		return
	}
	if !mfa.ValidateCode(req.Secret, req.Code) {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_code", "error_description": "Invalid or expired TOTP code"})
		return
	}
	codes, hashes, err := mfa.GenerateBackupCodes(mfa.DefaultBackupCodeCount)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := h.Store.SetMFAEnrollment(r.Context(), req.UserID, req.Secret, hashes); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"enrolled":     true,
		"backup_codes": codes,
		"user_id":      req.UserID,
	})
}

func decodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func (h *Handlers) handleMFAChallenge(w http.ResponseWriter, r *http.Request) {
	if !h.MFAEnabled {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "mfa_not_available"})
		return
	}
	if h.GrantStore == nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "MFA challenge requires grant store"})
		return
	}
	var req struct {
		ChallengeID string `json:"challenge_id"`
		Code        string `json:"code"`
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		_ = decodeJSON(r, &req)
	} else {
		_ = r.ParseForm()
		req.ChallengeID = r.FormValue("challenge_id")
		req.Code = r.FormValue("code")
	}
	if req.ChallengeID == "" || req.Code == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "challenge_id and code required"})
		return
	}
	pending, ok := h.GrantStore.ConsumeMFAPending(req.ChallengeID)
	if !ok || pending == nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid or expired MFA challenge"})
		return
	}
	en, err := h.Store.GetMFAEnrollment(r.Context(), pending.UserID)
	if err != nil || en == nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "MFA enrollment not found"})
		return
	}
	valid := false
	if mfa.ValidateCode(en.TOTPSecret, req.Code) {
		valid = true
	} else if consumed, err := h.Store.ConsumeBackupCode(r.Context(), pending.UserID, req.Code); err == nil && consumed {
		valid = true
	}
	if !valid {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid MFA code"})
		return
	}
	// Adaptive MFA: add IP to known list on successful verification
	if pending.ClientIP != "" {
		_ = h.Store.AddKnownIP(r.Context(), pending.UserID, pending.ClientIP)
	}
	u, err := h.Store.GetByID(r.Context(), pending.UserID)
	if err != nil || u == nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	ruleUser := &rules.User{UserID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified, Name: u.DisplayName, Nickname: u.DisplayName}
	if h.RulesRunner != nil {
		ruleUser, _ = h.RulesRunner.Run(ruleUser, &rules.Context{ClientID: pending.ClientID, Connection: "Username-Password-Authentication", Protocol: "oidc-basic-profile"})
	}
	email, displayName := ruleUser.Email, ruleUser.Name
	if displayName == "" {
		displayName = ruleUser.Nickname
	}
	if displayName == "" {
		displayName = email
	}
	aud := pending.Audience
	if aud == "" && pending.ClientID != "" {
		aud = pending.ClientID
	}
	if aud == "" {
		aud = "https://api.example.com"
	}
	accessLifetime := h.accessTokenLifetime()
	idLifetime := h.idTokenLifetime()
	sessionID := "sid_" + uuid.New().String()
	accessTok, err := h.Issuer.Issue(u.ID, aud, pending.ClientID, accessLifetime, ruleUser.AccessTokenClaims)
	if err != nil {
		metrics.TokenRequests.WithLabelValues("mfa_challenge", "error").Inc()
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	metrics.TokenRequests.WithLabelValues("mfa_challenge", "success").Inc()
	audit.LogToken("mfa_challenge", u.ID, pending.ClientID, true, nil)
	resp := map[string]interface{}{
		"access_token": accessTok,
		"token_type":   "Bearer",
		"expires_in":   accessLifetime,
	}
	if strings.Contains(pending.Scope, "openid") {
		opts := &token.IDTokenOptions{
			AMR:       []string{"pwd", "mfa"},
			SessionID: sessionID,
			CustomClaims: ruleUser.IDTokenClaims,
		}
		idTok, err := h.Issuer.IssueIDToken(u.ID, aud, pending.ClientID, idLifetime, pending.Scope, email, displayName, "", opts)
		if err == nil {
			resp["id_token"] = idTok
		}
	}
	if strings.Contains(pending.Scope, "offline_access") && h.GrantStore != nil {
		refreshTok := "rt_" + uuid.New().String()
		h.GrantStore.SaveRefreshToken(refreshTok, &grants.RefreshGrant{UserID: u.ID, ClientID: pending.ClientID, Scope: pending.Scope, SessionID: sessionID})
		resp["refresh_token"] = refreshTok
	}
	sendJSON(w, http.StatusOK, resp)
}
