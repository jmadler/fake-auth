package webauthn

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jmadler/auth2/internal/grants"
	"github.com/jmadler/auth2/internal/sessions"
)

const sessionCookieName = "auth2_session"

// RegisterDeps holds dependencies for registration/assertion handlers.
type RegisterDeps struct {
	SessionStore sessions.Store
	GrantStore   grants.GrantStore
}

// Router returns an http.Handler that routes /webauthn/register/begin, register/finish, assertion/begin, assertion/finish.
func (h *Handler) Router(deps RegisterDeps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /webauthn/register/begin", h.HandleRegisterBegin(deps))
	mux.HandleFunc("POST /webauthn/register/finish", h.HandleRegisterFinish(deps))
	mux.HandleFunc("POST /webauthn/assertion/begin", h.HandleAssertionBegin(deps))
	mux.HandleFunc("POST /webauthn/assertion/finish", h.HandleAssertionFinish(deps))
	return mux
}

// HandleRegisterBegin handles POST /webauthn/register/begin.
// Requires authenticated session. Returns challenge and options for navigator.credentials.create.
func (h *Handler) HandleRegisterBegin(deps RegisterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.enabled || h.WebAuthn == nil {
			http.Error(w, "WebAuthn not enabled", http.StatusNotFound)
			return
		}
		if deps.SessionStore == nil || deps.GrantStore == nil {
			http.Error(w, "Session or grant store not configured", http.StatusInternalServerError)
			return
		}
		c, err := r.Cookie(sessionCookieName)
		if err != nil || c.Value == "" {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		sess, ok := deps.SessionStore.Get(c.Value)
		if !ok || sess == nil {
			http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}
		u, err := h.Store.GetByID(r.Context(), sess.UserID)
		if err != nil || u == nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		wu, err := h.makeUser(r.Context(), u)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		creation, session, err := h.WebAuthn.BeginRegistration(wu)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sessionID := "wa_reg_" + uuid.New().String()
		sessionJSON, _ := json.Marshal(session)
		deps.GrantStore.SaveWebAuthnSession(sessionID, sessionJSON)
		resp := map[string]interface{}{
			"publicKey":   creation.Response,
			"sessionId":   sessionID,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleRegisterFinish handles POST /webauthn/register/finish.
// Body is the credential creation response. Query param: sessionId.
func (h *Handler) HandleRegisterFinish(deps RegisterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.enabled || h.WebAuthn == nil {
			http.Error(w, "WebAuthn not enabled", http.StatusNotFound)
			return
		}
		if deps.SessionStore == nil || deps.GrantStore == nil {
			http.Error(w, "Session or grant store not configured", http.StatusInternalServerError)
			return
		}
		sessionID := r.URL.Query().Get("sessionId")
		if sessionID == "" {
			http.Error(w, "sessionId required", http.StatusBadRequest)
			return
		}
		sessionJSON, ok := deps.GrantStore.ConsumeWebAuthnSession(sessionID)
		if !ok {
			http.Error(w, "Invalid or expired session", http.StatusBadRequest)
			return
		}
		var session webauthn.SessionData
		if err := json.Unmarshal(sessionJSON, &session); err != nil {
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}
		c, err := r.Cookie(sessionCookieName)
		if err != nil || c.Value == "" {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		sess, ok := deps.SessionStore.Get(c.Value)
		if !ok || sess == nil {
			http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}
		u, err := h.Store.GetByID(r.Context(), sess.UserID)
		if err != nil || u == nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		wu, err := h.makeUser(r.Context(), u)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		cred, err := h.WebAuthn.FinishRegistration(wu, session, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		stCred := webauthnCredentialToStore(cred, u.ID)
		stCred.CreatedAt = time.Now()
		if err := h.Store.CreateWebAuthnCredential(r.Context(), stCred); err != nil {
			http.Error(w, "Failed to save credential", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// HandleAssertionBegin handles POST /webauthn/assertion/begin.
// Body can include {"email": "user@example.com"} for passwordless. Returns options for navigator.credentials.get.
func (h *Handler) HandleAssertionBegin(deps RegisterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.enabled || h.WebAuthn == nil {
			http.Error(w, "WebAuthn not enabled", http.StatusNotFound)
			return
		}
		if deps.GrantStore == nil {
			http.Error(w, "Grant store not configured", http.StatusInternalServerError)
			return
		}
		var req struct {
			Email string `json:"email"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Email == "" {
			http.Error(w, "email required for passwordless", http.StatusBadRequest)
			return
		}
		u, err := h.Store.GetByEmail(r.Context(), req.Email)
		if err != nil || u == nil {
			// Don't reveal if user exists
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		wu, err := h.makeUser(r.Context(), u)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		if len(wu.credentials) == 0 {
			http.Error(w, "No passkeys registered for this account", http.StatusBadRequest)
			return
		}
		assertion, session, err := h.WebAuthn.BeginLogin(wu)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sessionID := "wa_assert_" + uuid.New().String()
		sessionJSON, _ := json.Marshal(session)
		deps.GrantStore.SaveWebAuthnSession(sessionID, sessionJSON)
		resp := map[string]interface{}{
			"publicKey": assertion,
			"sessionId": sessionID,
			"userId":    u.ID,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleAssertionFinish handles POST /webauthn/assertion/finish.
// Body is the assertion response. Query param: sessionId.
// Returns userId and optionally session token for the main handlers to use.
func (h *Handler) HandleAssertionFinish(deps RegisterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.enabled || h.WebAuthn == nil {
			http.Error(w, "WebAuthn not enabled", http.StatusNotFound)
			return
		}
		if deps.GrantStore == nil {
			http.Error(w, "Grant store not configured", http.StatusInternalServerError)
			return
		}
		sessionID := r.URL.Query().Get("sessionId")
		if sessionID == "" {
			http.Error(w, "sessionId required", http.StatusBadRequest)
			return
		}
		sessionJSON, ok := deps.GrantStore.ConsumeWebAuthnSession(sessionID)
		if !ok {
			http.Error(w, "Invalid or expired session", http.StatusBadRequest)
			return
		}
		var session webauthn.SessionData
		if err := json.Unmarshal(sessionJSON, &session); err != nil {
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}
		// We need DiscoverableUserHandler for passwordless - but we stored userId in session.
		// Actually BeginLogin returns session with UserID. So we can look up user and use FinishLogin.
		userID := string(session.UserID)
		if userID == "" {
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}
		u, err := h.Store.GetByID(r.Context(), userID)
		if err != nil || u == nil {
			http.Error(w, "User not found", http.StatusBadRequest)
			return
		}
		wu, err := h.makeUser(r.Context(), u)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		_, err = h.WebAuthn.FinishLogin(wu, session, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := map[string]interface{}{
			"status": "ok",
			"userId": u.ID,
			"email":  u.Email,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
