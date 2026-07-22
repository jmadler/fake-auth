package adminauth

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/jmadler/auth2/internal/token"
)

const (
	scopeReadUsers      = "read:users"
	scopeManageClients  = "manage:clients"
	scopeManageUsers    = "manage:users"
	scopeCreateUsers    = "create:users"
	scopeDeleteUsers    = "delete:users"
	scopeReadClients    = "read:clients"
	scopeReadRoles      = "read:roles"
	scopeCreateRoles    = "create:roles"
	scopeReadLogs       = "read:logs"
	scopeReadTokens     = "read:tokens"
	scopeStoreTokens    = "store:tokens"
)

// Config holds admin auth configuration.
type Config struct {
	AdminAPIKey   string       // ADMIN_API_KEY or MGMT_API_KEY when set
	ProductionMode bool        // when true, require auth even if AdminAPIKey is empty
	Issuer        *token.Issuer // for JWT validation, nil to skip JWT check
}

// LoadFromEnv populates Config from environment.
func LoadFromEnv(issuer *token.Issuer) Config {
	adminKey := os.Getenv("ADMIN_API_KEY")
	if adminKey == "" {
		adminKey = os.Getenv("MGMT_API_KEY")
	}
	productionMode := os.Getenv("PRODUCTION_MODE") == "true" || os.Getenv("PRODUCTION_MODE") == "1"
	return Config{
		AdminAPIKey:   adminKey,
		ProductionMode: productionMode,
		Issuer:        issuer,
	}
}

// hasAdminScope returns true if the JWT scope contains any admin-relevant scope.
func hasAdminScope(scopeStr string) bool {
	scopes := strings.Fields(scopeStr)
	allowed := map[string]bool{
		scopeReadUsers:     true,
		scopeManageClients: true,
		scopeManageUsers:   true,
		scopeCreateUsers:   true,
		scopeDeleteUsers:   true,
		scopeReadClients:   true,
		scopeReadRoles:     true,
		scopeCreateRoles:   true,
		scopeReadLogs:      true,
		scopeReadTokens:    true,
		scopeStoreTokens:   true,
	}
	for _, s := range scopes {
		if allowed[s] {
			return true
		}
	}
	return false
}

// Middleware returns an http.Handler that enforces admin auth on /api/v2/* routes.
// Excludes /health and /.well-known/*.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimSuffix(r.URL.Path, "/")

			// Exempt: health, ready, live, well-known, and non-management routes
			if path == "/health" || path == "/ready" || path == "/live" || strings.HasPrefix(path, "/.well-known/") {
				next.ServeHTTP(w, r)
				return
			}
			if !strings.HasPrefix(path, "/api/v2/") {
				next.ServeHTTP(w, r)
				return
			}

			// Dev mode: no AdminAPIKey and not production => allow unauthenticated
			if cfg.AdminAPIKey == "" && !cfg.ProductionMode {
				next.ServeHTTP(w, r)
				return
			}

			// Require Authorization: Bearer <token>
			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				sendUnauthorized(w, "Missing or invalid Authorization header")
				return
			}
			tokStr := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))

			// Check static API key first
			if cfg.AdminAPIKey != "" && tokStr == cfg.AdminAPIKey {
				next.ServeHTTP(w, r)
				return
			}

			// Validate JWT and check scopes
			if cfg.Issuer != nil {
				claims, err := cfg.Issuer.Validate(tokStr)
				if err == nil {
					if scope, ok := claims["scope"].(string); ok && hasAdminScope(scope) {
						next.ServeHTTP(w, r)
						return
					}
					// Token vault: allow token owner (valid JWT with sub) to access own entries
					if strings.HasPrefix(path, "/api/v2/token-vault") {
						if _, ok := claims["sub"].(string); ok {
							next.ServeHTTP(w, r)
							return
						}
					}
				}
			}

			sendUnauthorized(w, "Invalid or insufficient credentials for management API")
		})
	}
}

func sendUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized", "error_description": msg})
}
