package clients

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

// Config holds per-client OAuth configuration.
type ClientConfig struct {
	ClientSecret  string   `json:"client_secret"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"` // empty = allow all
}

// Registry provides client validation. Thread-safe.
type Registry struct {
	mu      sync.RWMutex
	clients map[string]*ClientConfig
	// RequireSecretForCodes: if true, authorization_code requires valid client_secret for configured clients
	RequireSecretForCodes bool
}

// NewRegistry returns an empty registry. Use LoadFromEnv or Add to populate.
func NewRegistry() *Registry {
	return &Registry{clients: make(map[string]*ClientConfig)}
}

// LoadFromEnv reads CLIENT_REGISTRY JSON from env. Format: {"client_id":{"client_secret":"x","redirect_uris":["http://..."],"allowed_scopes":["openid","profile"]}}
func (r *Registry) LoadFromEnv() error {
	raw := os.Getenv("CLIENT_REGISTRY")
	if raw == "" {
		return nil
	}
	var m map[string]*ClientConfig
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, cfg := range m {
		if cfg != nil {
			r.clients[id] = cfg
		}
	}
	return nil
}

// Add registers or updates a client config.
func (r *Registry) Add(clientID string, cfg *ClientConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.clients == nil {
		r.clients = make(map[string]*ClientConfig)
	}
	r.clients[clientID] = cfg
}

// Get returns the config for a client, or nil if not configured.
func (r *Registry) Get(clientID string) *ClientConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.clients[clientID]
}

// ValidateSecret returns true if client has no config (public client) or secret matches.
func (r *Registry) ValidateSecret(clientID, secret string) bool {
	cfg := r.Get(clientID)
	if cfg == nil {
		return true // public client
	}
	if cfg.ClientSecret == "" {
		return true
	}
	return secret == cfg.ClientSecret
}

// IsConfidential returns true if client has a secret configured.
func (r *Registry) IsConfidential(clientID string) bool {
	cfg := r.Get(clientID)
	return cfg != nil && cfg.ClientSecret != ""
}

// ValidateRedirectURI returns true if redirect_uri is allowed for the client.
func (r *Registry) ValidateRedirectURI(clientID, redirectURI string) bool {
	cfg := r.Get(clientID)
	if cfg == nil || len(cfg.RedirectURIs) == 0 {
		return true
	}
	for _, u := range cfg.RedirectURIs {
		if u == redirectURI {
			return true
		}
	}
	return false
}

// ValidateScope returns true if all requested scopes are allowed. Empty allowed = allow all.
func (r *Registry) ValidateScope(clientID string, requestedScope string) bool {
	cfg := r.Get(clientID)
	if cfg == nil || len(cfg.AllowedScopes) == 0 {
		return true
	}
	requested := strings.Fields(requestedScope)
	allowedSet := make(map[string]bool)
	for _, s := range cfg.AllowedScopes {
		allowedSet[s] = true
	}
	for _, s := range requested {
		if !allowedSet[s] {
			return false
		}
	}
	return true
}
