package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jmadler/auth2/internal/enterprise"
	"github.com/jmadler/auth2/internal/grants"
	"github.com/jmadler/auth2/internal/saml"
	"github.com/jmadler/auth2/internal/store"
)

// SAMLConfig holds SAML IdP configuration.
type SAMLConfig struct {
	EntityID string
	CertPEM  string
	KeyPEM   string
}

// handleSAMLMetadata serves IdP metadata XML.
func (h *Handlers) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	cfg := h.SAMLConfig
	if cfg == nil {
		cfg = &SAMLConfig{}
	}
	baseURL := strings.TrimSuffix(h.issuerURL(), "/")
	if cfg.EntityID == "" {
		cfg.EntityID = baseURL
	}
	samlCfg := saml.Config{EntityID: cfg.EntityID, CertPEM: cfg.CertPEM, BaseURL: baseURL}
	meta, err := saml.BuildMetadata(samlCfg)
	if err != nil {
		http.Error(w, "Failed to build metadata", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(meta)
}

// handleSAMLSSO handles SAML SSO (both GET redirect and POST).
func (h *Handlers) handleSAMLSSO(w http.ResponseWriter, r *http.Request) {
	var samlRequest, relayState string
	if r.Method == http.MethodGet {
		samlRequest = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	} else {
		_ = r.ParseForm()
		samlRequest = r.FormValue("SAMLRequest")
		relayState = r.FormValue("RelayState")
	}
	if samlRequest == "" {
		http.Error(w, "SAMLRequest required", http.StatusBadRequest)
		return
	}
	authReq, err := saml.ParseAuthnRequestFromParam(samlRequest)
	if err != nil {
		http.Error(w, "Invalid SAMLRequest", http.StatusBadRequest)
		return
	}
	sp, err := h.Store.GetSAMLServiceProviderByEntityID(r.Context(), authReq.Issuer.Value)
	if err != nil || sp == nil {
		http.Error(w, "Unknown Service Provider", http.StatusBadRequest)
		return
	}
	acsURL := authReq.AssertionConsumerServiceURL
	if acsURL == "" {
		acsURL = sp.ACSURL
	}
	samlSP := &saml.ServiceProvider{EntityID: sp.EntityID, ACSURL: acsURL, Certificate: sp.Certificate}
	cfg := h.SAMLConfig
	if cfg == nil {
		cfg = &SAMLConfig{}
	}
	baseURL := strings.TrimSuffix(h.issuerURL(), "/")
	if cfg.EntityID == "" {
		cfg.EntityID = baseURL
	}
	samlCfg := saml.Config{EntityID: cfg.EntityID, CertPEM: cfg.CertPEM, BaseURL: baseURL}
	// Check if user is authenticated
	var u *store.User
	if h.SessionStore != nil {
		if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			if sess, ok := h.SessionStore.Get(c.Value); ok && sess != nil {
				u, _ = h.Store.GetByID(r.Context(), sess.UserID)
			}
		}
	}
	if u == nil {
		// Redirect to login; redirect_uri will bring user back to /saml/sso with SAMLRequest
		samlReq := samlRequest
		if r.Method == http.MethodGet {
			samlReq = r.URL.Query().Get("SAMLRequest")
		}
		returnTo := baseURL + "/saml/sso?SAMLRequest=" + url.QueryEscape(samlReq)
		if relayState != "" {
			returnTo += "&RelayState=" + url.QueryEscape(relayState)
		}
		loginURL := h.issuerURL() + "/login?redirect_uri=" + url.QueryEscape(returnTo) + "&state=saml&client_id=saml"
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	data := &saml.AssertionData{
		NameID:     u.ID,
		Email:      u.Email,
		Attributes: map[string]string{"email": u.Email, "name": u.DisplayName},
	}
	respXML, err := saml.BuildResponse(samlCfg, authReq, samlSP, data)
	if err != nil {
		http.Error(w, "Failed to build response", http.StatusInternalServerError)
		return
	}
	samlResponse := base64.StdEncoding.EncodeToString(respXML)
	html := saml.BuildPOSTForm(acsURL, samlResponse, relayState)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleCreateSAMLSP registers a SAML Service Provider.
func (h *Handlers) handleCreateSAMLSP(w http.ResponseWriter, r *http.Request) {
	setRateLimitHeaders(w)
	var req struct {
		EntityID    string `json:"entity_id"`
		ACSURL      string `json:"acs_url"`
		Certificate string `json:"certificate"`
		MetadataURL string `json:"metadata_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body", "message": "Invalid JSON"})
		return
	}
	if req.EntityID == "" || req.ACSURL == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "message": "entity_id and acs_url required"})
		return
	}
	sp := &store.SAMLServiceProvider{
		ID:          "sp_" + uuid.New().String(),
		EntityID:    req.EntityID,
		ACSURL:      req.ACSURL,
		Certificate: req.Certificate,
		MetadataURL: req.MetadataURL,
	}
	if err := h.Store.CreateSAMLServiceProvider(r.Context(), sp); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusCreated, map[string]interface{}{
		"id":          sp.ID,
		"entity_id":   sp.EntityID,
		"acs_url":     sp.ACSURL,
		"metadata_url": sp.MetadataURL,
	})
}

// handleLoginEnterprise initiates enterprise OIDC login.
func (h *Handlers) handleLoginEnterprise(w http.ResponseWriter, r *http.Request) {
	connection := r.URL.Query().Get("connection")
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "openid"
	}
	audience := r.URL.Query().Get("audience")
	responseType := r.URL.Query().Get("response_type")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	if connection == "" || clientID == "" || redirectURI == "" {
		http.Error(w, "connection, client_id, redirect_uri required", http.StatusBadRequest)
		return
	}
	ec, err := h.Store.GetOIDCEnterpriseConnectionByName(r.Context(), connection)
	if err != nil || ec == nil {
		http.Error(w, "Unknown enterprise connection", http.StatusBadRequest)
		return
	}
	if h.GrantStore == nil {
		http.Error(w, "Enterprise login not configured", http.StatusInternalServerError)
		return
	}
	callbackURL := strings.TrimSuffix(h.issuerURL(), "/") + "/callback/enterprise"
	oauthState := "ent_" + uuid.New().String()
	h.GrantStore.SaveSocialState(oauthState, &grants.SocialState{
		RedirectURI:         redirectURI,
		ClientID:            clientID,
		Scope:               scope,
		State:               state,
		Audience:            audience,
		ResponseType:        responseType,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Connection:          connection,
	})
	prov := enterprise.NewProvider(&enterprise.OIDCConnection{
		Name:         ec.Name,
		IssuerURL:    ec.IssuerURL,
		ClientID:     ec.ClientID,
		ClientSecret: ec.ClientSecret,
		Scope:        ec.Scope,
		DomainHint:   ec.DomainHint,
	})
	authURL := prov.AuthURL(oauthState, callbackURL)
	if authURL == "" {
		http.Error(w, "Failed to build enterprise auth URL", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleEnterpriseCallback handles OIDC callback from enterprise IdP.
func (h *Handlers) handleEnterpriseCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>state and code are required.</p></body></html>`))
		return
	}
	if h.GrantStore == nil {
		http.Error(w, "Enterprise login not configured", http.StatusInternalServerError)
		return
	}
	ss, ok := h.GrantStore.ConsumeSocialState(state)
	if !ok || ss == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Invalid or expired state. Please try again.</p></body></html>`))
		return
	}
	connection := ss.Connection
	// Org-scoped enterprise: enterprise:ecID
	if strings.HasPrefix(connection, "enterprise:") {
		ecID := strings.TrimPrefix(connection, "enterprise:")
		ec, err := h.Store.GetEnterpriseConnection(r.Context(), ecID)
		if err != nil || ec == nil {
			redirectWithError(w, r, ss.RedirectURI, ss.State, "invalid_connection", "Enterprise connection not found")
			return
		}
		callbackURL := strings.TrimSuffix(h.issuerURL(), "/") + "/callback/enterprise"
		prov := enterprise.NewProvider(&enterprise.OIDCConnection{
			Name:         ec.Name,
			IssuerURL:    ec.IssuerURL,
			ClientID:     ec.ClientID,
			ClientSecret: ec.ClientSecret,
			Scope:        "openid email profile",
			DomainHint:   ec.DomainHint,
		})
		userInfo, err := prov.ExchangeCode(r.Context(), code, callbackURL)
		if err != nil {
			redirectWithError(w, r, ss.RedirectURI, ss.State, "server_error", "Failed to exchange code")
			return
		}
		h.finishEnterpriseAuth(w, r, connection, ss, userInfo, ec.OrgID)
		return
	}
	// Global OIDC enterprise by name
	ec, err := h.Store.GetOIDCEnterpriseConnectionByName(r.Context(), connection)
	if err != nil || ec == nil {
		redirectWithError(w, r, ss.RedirectURI, ss.State, "invalid_connection", "Unknown enterprise connection")
		return
	}
	callbackURL := strings.TrimSuffix(h.issuerURL(), "/") + "/callback/enterprise"
	prov := enterprise.NewProvider(&enterprise.OIDCConnection{
		Name:         ec.Name,
		IssuerURL:    ec.IssuerURL,
		ClientID:     ec.ClientID,
		ClientSecret: ec.ClientSecret,
		Scope:        ec.Scope,
		DomainHint:   ec.DomainHint,
	})
	userInfo, err := prov.ExchangeCode(r.Context(), code, callbackURL)
	if err != nil {
		redirectWithError(w, r, ss.RedirectURI, ss.State, "server_error", "Failed to exchange code")
		return
	}
	h.finishEnterpriseAuth(w, r, connection, ss, userInfo, "")
}

// finishEnterpriseAuth completes enterprise auth after code exchange: create/link user, set session, redirect with code.
func (h *Handlers) finishEnterpriseAuth(w http.ResponseWriter, r *http.Request, connection string, ss *grants.SocialState, userInfo *enterprise.UserInfo, orgID string) {
	if userInfo.Email == "" {
		redirectWithError(w, r, ss.RedirectURI, ss.State, "server_error", "Provider did not return email")
		return
	}
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
		uid := "auth0|" + uuid.New().String()
		displayName := userInfo.Name
		if displayName == "" {
			displayName = userInfo.Email
		}
		socialPass := "ent_" + uuid.New().String() + uuid.New().String()[:8]
		u = &store.User{
			ID:             uid,
			Email:          userInfo.Email,
			DisplayName:    displayName,
			EmailVerified:  true,
			OrganizationID: 1,
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
	if orgID != "" {
		_ = h.Store.AddOrgMember(r.Context(), orgID, u.ID, "member")
	}
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
	redirectURL, _ := url.Parse(ss.RedirectURI)
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
