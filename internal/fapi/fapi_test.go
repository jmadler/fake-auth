package fapi

import (
	"net/http"
	"os"
	"testing"
)

func TestEnabled(t *testing.T) {
	orig := os.Getenv("FAPI_ENABLED")
	defer os.Setenv("FAPI_ENABLED", orig)

	os.Unsetenv("FAPI_ENABLED")
	if Enabled() {
		t.Error("Expected disabled when FAPI_ENABLED unset")
	}
	os.Setenv("FAPI_ENABLED", "true")
	if !Enabled() {
		t.Error("Expected enabled when FAPI_ENABLED=true")
	}
	os.Setenv("FAPI_ENABLED", "TRUE")
	if !Enabled() {
		t.Error("Expected enabled when FAPI_ENABLED=TRUE (case insensitive)")
	}
	os.Setenv("FAPI_ENABLED", "false")
	if Enabled() {
		t.Error("Expected disabled when FAPI_ENABLED=false")
	}
}

func TestValidateFAPIRequest_Authorize_PKCE(t *testing.T) {
	restore := setEnv("FAPI_ENABLED", "true")
	defer restore()

	r, _ := http.NewRequest("GET", "/authorize", nil)
	// Missing code_challenge
	err := ValidateFAPIRequest(r, map[string]string{}, false)
	if err == nil {
		t.Fatal("Expected error when code_challenge missing")
	}
	if err["error"] != "invalid_request" {
		t.Errorf("Expected invalid_request, got %v", err)
	}
}

func TestValidateFAPIRequest_Authorize_CodeChallengeMethod(t *testing.T) {
	restore := setEnv("FAPI_ENABLED", "true")
	defer restore()

	r, _ := http.NewRequest("GET", "/authorize", nil)
	err := ValidateFAPIRequest(r, map[string]string{
		"code_challenge":        "abc123",
		"code_challenge_method": "plain",
	}, false)
	if err == nil {
		t.Fatal("Expected error when code_challenge_method is not S256")
	}
}

func TestValidateFAPIRequest_Authorize_ResponseMode(t *testing.T) {
	restore := setEnv("FAPI_ENABLED", "true")
	defer restore()

	r, _ := http.NewRequest("GET", "/authorize", nil)
	err := ValidateFAPIRequest(r, map[string]string{
		"code_challenge": "abc123",
		"response_mode":  "form_post",
	}, false)
	if err == nil {
		t.Fatal("Expected error when response_mode is form_post")
	}
}

func TestValidateFAPIRequest_Authorize_Valid(t *testing.T) {
	restore := setEnv("FAPI_ENABLED", "true")
	defer restore()

	r, _ := http.NewRequest("GET", "/authorize", nil)
	err := ValidateFAPIRequest(r, map[string]string{
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
		"response_mode":         "query",
	}, false)
	if err != nil {
		t.Errorf("Expected nil for valid request, got %v", err)
	}
}

// Note: ValidateFAPIRequest always validates. Handlers call it only when FAPI_ENABLED=true.

func TestValidateFAPIRequest_TokenRequest(t *testing.T) {
	restore := setEnv("FAPI_ENABLED", "true")
	defer restore()

	r, _ := http.NewRequest("POST", "/oauth/token", nil)
	// Token request: PKCE check is for authorize, not token
	err := ValidateFAPIRequest(r, map[string]string{}, true)
	if err != nil {
		t.Errorf("Token request should not require code_challenge in ValidateFAPIRequest, got %v", err)
	}
}

func setEnv(k, v string) func() {
	old := os.Getenv(k)
	os.Setenv(k, v)
	return func() {
		os.Setenv(k, old)
	}
}
