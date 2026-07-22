package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmadler/auth2/internal/store"
)

// extractOrgIDFromPath extracts org ID from /api/v2/organizations/{id} or /api/v2/organizations/{id}/...
func extractOrgIDFromPath(path, prefix string) string {
	path = strings.TrimSuffix(path, "/")
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	if idx := strings.Index(rest, "/"); idx >= 0 {
		return rest[:idx]
	}
	return rest
}

func (h *Handlers) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	orgs, err := h.Store.ListOrganizations(r.Context())
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for _, o := range orgs {
		out = append(out, orgToResponse(&o))
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleCreateOrganization(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	var req struct {
		Name        string                 `json:"name"`
		DisplayName string                 `json:"display_name"`
		Metadata    map[string]interface{} `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "Invalid JSON"})
		return
	}
	if req.Name == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "name is required"})
		return
	}
	org := &store.Organization{
		ID:          "org_" + uuid.New().String(),
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Metadata:    req.Metadata,
	}
	if err := h.Store.CreateOrganization(r.Context(), org); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusCreated, orgToResponse(org))
}

func (h *Handlers) handleGetOrganization(w http.ResponseWriter, r *http.Request, path string) {
	id := extractOrgIDFromPath(path, "/api/v2/organizations/")
	if id == "" || strings.Contains(id, "/") {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	org, err := h.Store.GetOrganization(r.Context(), id)
	if err != nil || org == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found", "message": "Organization does not exist"})
		return
	}
	sendJSON(w, http.StatusOK, orgToResponse(org))
}

func (h *Handlers) handlePatchOrganization(w http.ResponseWriter, r *http.Request, path string) {
	id := extractOrgIDFromPath(path, "/api/v2/organizations/")
	if id == "" || strings.Contains(id, "/") {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "Invalid JSON"})
		return
	}
	updates := make(map[string]interface{})
	if v, ok := req["name"]; ok {
		if s, ok := v.(string); ok {
			updates["name"] = s
		}
	}
	if v, ok := req["display_name"]; ok {
		if s, ok := v.(string); ok {
			updates["display_name"] = s
		}
	}
	if v, ok := req["metadata"]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			updates["metadata"] = m
		}
	}
	if len(updates) == 0 {
		org, _ := h.Store.GetOrganization(r.Context(), id)
		if org == nil {
			sendJSON(w, http.StatusNotFound, map[string]string{"error": "Not found"})
			return
		}
		sendJSON(w, http.StatusOK, orgToResponse(org))
		return
	}
	if err := h.Store.UpdateOrganization(r.Context(), id, updates); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	org, _ := h.Store.GetOrganization(r.Context(), id)
	sendJSON(w, http.StatusOK, orgToResponse(org))
}

func (h *Handlers) handleDeleteOrganization(w http.ResponseWriter, r *http.Request, path string) {
	id := extractOrgIDFromPath(path, "/api/v2/organizations/")
	if id == "" || strings.Contains(id, "/") {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	if err := h.Store.DeleteOrganization(r.Context(), id); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusNoContent, nil)
}

func (h *Handlers) handleListOrgMembers(w http.ResponseWriter, r *http.Request, path string) {
	// path is /api/v2/organizations/{id}/members
	id := strings.TrimPrefix(path, "/api/v2/organizations/")
	id = strings.TrimSuffix(id, "/members")
	if id == "" || strings.Contains(id, "/") {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	members, err := h.Store.ListOrgMembers(r.Context(), id)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for _, m := range members {
		out = append(out, map[string]interface{}{
			"user_id": m.UserID,
			"role":    m.Role,
		})
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleAddOrgMember(w http.ResponseWriter, r *http.Request, path string) {
	id := strings.TrimPrefix(path, "/api/v2/organizations/")
	id = strings.TrimSuffix(id, "/members")
	if id == "" || strings.Contains(id, "/") {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "Invalid JSON"})
		return
	}
	if req.UserID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "user_id is required"})
		return
	}
	role := req.Role
	if role == "" {
		role = "member"
	}
	if err := h.Store.AddOrgMember(r.Context(), id, req.UserID, role); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusCreated, map[string]interface{}{
		"user_id": req.UserID,
		"role":    role,
	})
}

func (h *Handlers) handleRemoveOrgMember(w http.ResponseWriter, r *http.Request, path string) {
	// path: /api/v2/organizations/{id}/members - DELETE with user_id in body or query
	id := strings.TrimPrefix(path, "/api/v2/organizations/")
	id = strings.TrimSuffix(id, "/members")
	if id == "" || strings.Contains(id, "/") {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	var userID string
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var req struct {
			UserID string `json:"user_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			userID = req.UserID
		}
	}
	if userID == "" {
		userID = r.URL.Query().Get("user_id")
	}
	if userID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "user_id is required"})
		return
	}
	setRateLimitHeaders(w)
	if err := h.Store.RemoveOrgMember(r.Context(), id, userID); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) handleListOrgConnections(w http.ResponseWriter, r *http.Request, path string) {
	id := strings.TrimPrefix(path, "/api/v2/organizations/")
	id = strings.TrimSuffix(id, "/connections")
	if id == "" || strings.Contains(id, "/") {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	connIDs, err := h.Store.ListOrgConnections(r.Context(), id)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// Also include enterprise connections
	enterpriseConns, err := h.Store.ListEnterpriseConnections(r.Context(), id)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	var out []map[string]interface{}
	for _, cid := range connIDs {
		conn, _ := h.Store.GetConnectionByID(r.Context(), cid)
		if conn != nil {
			out = append(out, map[string]interface{}{
				"connection_id": cid,
				"name":          conn.Name,
				"type":         "auth0",
			})
		}
	}
	for _, ec := range enterpriseConns {
		out = append(out, map[string]interface{}{
			"connection_id": ec.ID,
			"name":          ec.Name,
			"type":          "oidc",
			"domain_hint":   ec.DomainHint,
		})
	}
	sendJSON(w, http.StatusOK, out)
}

func (h *Handlers) handleAddOrgConnection(w http.ResponseWriter, r *http.Request, path string) {
	id := strings.TrimPrefix(path, "/api/v2/organizations/")
	id = strings.TrimSuffix(id, "/connections")
	if id == "" || strings.Contains(id, "/") {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	var req struct {
		ConnectionID string `json:"connection_id"`
		Type         string `json:"type"`
		// OIDC self-service SSO
		IssuerURL    string `json:"issuer_url"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Name         string `json:"name"`
		DomainHint   string `json:"domain_hint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "Invalid JSON"})
		return
	}
	if req.Type == "oidc" {
		if req.IssuerURL == "" || req.ClientID == "" {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "issuer_url and client_id required for OIDC"})
			return
		}
		ec := &store.EnterpriseConnection{
			ID:           "ec_" + uuid.New().String(),
			OrgID:        id,
			Name:         req.Name,
			DomainHint:   req.DomainHint,
			IssuerURL:    req.IssuerURL,
			ClientID:     req.ClientID,
			ClientSecret: req.ClientSecret,
		}
		if ec.Name == "" {
			ec.Name = ec.ID
		}
		if err := h.Store.CreateEnterpriseConnection(r.Context(), ec); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		sendJSON(w, http.StatusCreated, map[string]interface{}{
			"connection_id": ec.ID,
			"name":          ec.Name,
			"type":          "oidc",
			"domain_hint":   ec.DomainHint,
		})
		return
	}
	// Standard connection link
	if req.ConnectionID == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "connection_id is required"})
		return
	}
	if err := h.Store.SetOrgConnection(r.Context(), id, req.ConnectionID); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	conn, _ := h.Store.GetConnectionByID(r.Context(), req.ConnectionID)
	resp := map[string]interface{}{"connection_id": req.ConnectionID}
	if conn != nil {
		resp["name"] = conn.Name
	}
	sendJSON(w, http.StatusCreated, resp)
}

func (h *Handlers) handleCreateOrgInvitation(w http.ResponseWriter, r *http.Request, path string) {
	id := strings.TrimPrefix(path, "/api/v2/organizations/")
	id = strings.TrimSuffix(id, "/invitations")
	if id == "" || strings.Contains(id, "/") {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	setRateLimitHeaders(w)
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "Invalid JSON"})
		return
	}
	if req.Email == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "email is required"})
		return
	}
	role := req.Role
	if role == "" {
		role = "member"
	}
	token := "inv_" + uuid.New().String()
	inv := &store.Invitation{
		ID:        "inv_" + uuid.New().String(),
		OrgID:     id,
		Email:     req.Email,
		Role:      role,
		Token:     token,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	if _, err := h.Store.CreateInvitation(r.Context(), inv); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusCreated, map[string]interface{}{
		"id":        inv.ID,
		"org_id":    inv.OrgID,
		"email":     inv.Email,
		"role":      inv.Role,
		"expires_at": inv.ExpiresAt.Format(time.RFC3339),
		"invitation_url": "/organizations/accept-invitation?invitation=" + token,
	})
}

func (h *Handlers) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("invitation")
	if token == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "invitation token is required"})
		return
	}
	inv, err := h.Store.GetInvitationByToken(r.Context(), token)
	if err != nil || inv == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "invalid_invitation", "message": "Invitation not found or expired"})
		return
	}
	// Return invitation details - the actual accept flow would create/link user and add to org
	// For now return the invitation info; client can show a signup/login form with org context
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"invitation_id": inv.ID,
		"org_id":        inv.OrgID,
		"email":         inv.Email,
		"role":          inv.Role,
	})
}

// buildEnterpriseOIDCAuthURL builds the authorization URL for an enterprise OIDC IdP.
// Fetches discovery from issuer_url/.well-known/openid-configuration and uses authorization_endpoint.
func buildEnterpriseOIDCAuthURL(ec *store.EnterpriseConnection, callbackURL, clientID, scope, state string) (string, error) {
	base := strings.TrimSuffix(ec.IssuerURL, "/")
	discoveryURL := base + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		// Fallback: many IdPs use {issuer}/authorize or {issuer}/protocol/openid-connect/auth
		authEndpoint := base + "/authorize"
		u, _ := url.Parse(authEndpoint)
		q := u.Query()
		q.Set("client_id", ec.ClientID)
		q.Set("redirect_uri", callbackURL)
		q.Set("response_type", "code")
		q.Set("scope", scope)
		if state != "" {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	defer resp.Body.Close()
	var doc struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || doc.AuthorizationEndpoint == "" {
		authEndpoint := base + "/authorize"
		u, _ := url.Parse(authEndpoint)
		q := u.Query()
		q.Set("client_id", ec.ClientID)
		q.Set("redirect_uri", callbackURL)
		q.Set("response_type", "code")
		q.Set("scope", scope)
		if state != "" {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	u, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", ec.ClientID)
	q.Set("redirect_uri", callbackURL)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func orgToResponse(o *store.Organization) map[string]interface{} {
	resp := map[string]interface{}{
		"id":        o.ID,
		"name":      o.Name,
		"created_at": o.CreatedAt.Format(time.RFC3339),
	}
	if o.DisplayName != "" {
		resp["display_name"] = o.DisplayName
	}
	if o.Metadata != nil {
		resp["metadata"] = o.Metadata
	}
	return resp
}
