package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jmadler/auth2/internal/store"
	"github.com/jmadler/auth2/internal/tokenvault"
)

func (h *Handlers) handleTokenVaultStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req tokenvault.StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid JSON body"})
		return
	}
	if msg := req.Validate(); msg != "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": msg})
		return
	}
	userID, err := h.tokenVaultUserID(r)
	if err != nil || userID == "" {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "error_description": "Valid Bearer token required"})
		return
	}
	enc, err := tokenvault.Encrypt(req.AccessToken)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": err.Error()})
		return
	}
	entry := &store.TokenVaultEntry{
		Name:                 req.Name,
		UserID:               userID,
		AccessTokenEncrypted: enc,
		Metadata:             req.MetadataJSON(),
	}
	vaultID, err := h.Store.SaveTokenVaultEntry(r.Context(), entry)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	sendJSON(w, http.StatusOK, map[string]interface{}{"vault_id": vaultID})
}

func (h *Handlers) handleTokenVaultGet(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	// Path: /api/v2/token-vault/{name}
	prefix := "/api/v2/token-vault/"
	if !strings.HasPrefix(path, prefix) {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(path, prefix)
	if name == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "name is required"})
		return
	}
	userID, admin, err := h.tokenVaultAuth(r)
	if err != nil || userID == "" {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "error_description": "Valid Bearer token required"})
		return
	}
	var entry *store.TokenVaultEntry
	if admin {
		// Admin can get by name - need to get by name for any user; we don't have user_id in path
		// For admin, we'd need name+user_id. Simplification: admin passes ?user_id= in query
		reqUserID := r.URL.Query().Get("user_id")
		if reqUserID != "" {
			entry, err = h.Store.GetTokenVaultEntry(r.Context(), name, reqUserID)
		} else {
			// Admin without user_id: return 400 for now
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "user_id query param required for admin lookup"})
			return
		}
	} else {
		entry, err = h.Store.GetTokenVaultEntry(r.Context(), name, userID)
	}
	if err != nil || entry == nil {
		sendJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "error_description": "Token vault entry not found"})
		return
	}
	dec, err := tokenvault.Decrypt(entry.AccessTokenEncrypted)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	resp := map[string]interface{}{
		"vault_id":      entry.ID,
		"name":          entry.Name,
		"access_token":  dec,
		"created_at":    entry.CreatedAt,
	}
	if entry.Metadata != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(entry.Metadata), &meta) == nil {
			resp["metadata"] = meta
		}
	}
	sendJSON(w, http.StatusOK, resp)
}

// tokenVaultUserID returns the user ID from the Bearer token (for store).
func (h *Handlers) tokenVaultUserID(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return "", nil
	}
	tokStr := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	claims, err := h.Issuer.Validate(tokStr)
	if err != nil {
		return "", err
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub, nil
	}
	return "", nil
}

// tokenVaultAuth returns (userID, isAdmin, error). Admin can access any user's entries.
func (h *Handlers) tokenVaultAuth(r *http.Request) (userID string, admin bool, err error) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return "", false, nil
	}
	tokStr := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	// Check admin API key first
	if h.AdminAPIKey != "" && tokStr == h.AdminAPIKey {
		return "", true, nil
	}
	claims, err := h.Issuer.Validate(tokStr)
	if err != nil {
		return "", false, err
	}
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	admin = strings.Contains(scope, "read:tokens") || strings.Contains(scope, "store:tokens") ||
		strings.Contains(scope, "read:users") || strings.Contains(scope, "manage:")
	return sub, admin, nil
}
