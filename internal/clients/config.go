package clients

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/jmadler/auth2/internal/logging"
)

// Config holds per-client OAuth configuration.
type ClientConfig struct {
	ClientSecret    string   `json:"client_secret"`
	RedirectURIs    []string `json:"redirect_uris"`
	AllowedScopes   []string `json:"allowed_scopes"`   // empty = allow all
	AllowedOrigins  []string `json:"allowed_origins"`  // CORS origins for this client
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
	return r.loadFromJSON([]byte(raw))
}

// LoadFromFile reads client config from a file. If CLIENT_REGISTRY_FILE is set, use it instead of env.
// If CLIENT_REGISTRY_KEY is set (32-byte hex for AES-256), the file is decrypted before parsing.
// Format: same JSON as CLIENT_REGISTRY.
func (r *Registry) LoadFromFile() error {
	path := os.Getenv("CLIENT_REGISTRY_FILE")
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	keyHex := os.Getenv("CLIENT_REGISTRY_KEY")
	if keyHex != "" {
		key, err := hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil || len(key) != 32 {
			return err // invalid key
		}
		data, err = decryptAES256GCM(key, data)
		if err != nil {
			return err
		}
	}
	return r.loadFromJSON(data)
}

func decryptAES256GCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, io.ErrUnexpectedEOF
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (r *Registry) loadFromJSON(data []byte) error {
	var m map[string]*ClientConfig
	if err := json.Unmarshal(data, &m); err != nil {
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

// ValidateAndWarn checks client config and logs warnings for invalid redirect_uris.
func (r *Registry) ValidateAndWarn() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for clientID, cfg := range r.clients {
		if cfg == nil {
			continue
		}
		for _, uri := range cfg.RedirectURIs {
			if uri == "" {
				logging.Warn(context.Background(), "client has empty redirect_uri", "client_id", clientID)
				continue
			}
			u, err := url.Parse(uri)
			if err != nil {
				logging.Warn(context.Background(), "client has invalid redirect_uri", "client_id", clientID, "redirect_uri", uri, "error", err)
				continue
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				logging.Warn(context.Background(), "redirect_uri should use http or https scheme", "client_id", clientID, "redirect_uri", uri)
			}
		}
	}
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

// AllowedOrigins returns all unique allowed_origins from registered clients.
func (r *Registry) AllowedOrigins() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[string]bool)
	var out []string
	for _, cfg := range r.clients {
		if cfg == nil {
			continue
		}
		for _, o := range cfg.AllowedOrigins {
			if o != "" && !seen[o] {
				seen[o] = true
				out = append(out, o)
			}
		}
	}
	return out
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
