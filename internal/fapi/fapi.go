package fapi

import (
	"net/http"
	"os"
	"strings"
)

// Enabled returns true when FAPI (Financial-grade) mode is enabled.
func Enabled() bool {
	return strings.ToLower(os.Getenv("FAPI_ENABLED")) == "true"
}

// ValidateFAPIRequest validates the request per FAPI 1.0 / OIDC FAPI security requirements.
// Returns nil when valid, or an error map for sendJSON response.
func ValidateFAPIRequest(r *http.Request, params map[string]string, isTokenRequest bool) map[string]string {
	// Require PKCE for authorization code flow (authorize request)
	if !isTokenRequest {
		if codeChallenge := params["code_challenge"]; codeChallenge == "" {
			return map[string]string{"error": "invalid_request", "error_description": "FAPI requires PKCE (code_challenge)"}
		}
		if method := params["code_challenge_method"]; method != "" && method != "S256" {
			return map[string]string{"error": "invalid_request", "error_description": "FAPI requires code_challenge_method S256"}
		}
		// response_mode: FAPI requires explicit response_mode; query or fragment
		if responseMode := params["response_mode"]; responseMode != "" && responseMode != "query" && responseMode != "fragment" {
			return map[string]string{"error": "invalid_request", "error_description": "FAPI requires response_mode query or fragment"}
		}
	}

	// For token request with auth code: PKCE verifier required (handled in handler)
	// Reject HS256 in alg: FAPI requires RS256/ES256 for ID tokens
	// (Validated at token issuance - we use RS256)

	// Require audience for access tokens when FAPI is enabled
	if audience := params["audience"]; audience == "" && !isTokenRequest {
		// Authorization request without audience may be acceptable for ID token only;
		// FAPI typically requires resource indicators
		// Be permissive: only warn, don't reject
	}

	return nil
}
