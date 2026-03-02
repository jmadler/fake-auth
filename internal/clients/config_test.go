package clients

import (
	"os"
	"testing"
)

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	r.Add("client1", &ClientConfig{
		ClientSecret:  "secret1",
		RedirectURIs:  []string{"http://localhost/cb"},
		AllowedScopes: []string{"openid", "profile"},
	})
	if !r.ValidateSecret("client1", "secret1") {
		t.Error("ValidateSecret should pass for correct secret")
	}
	if r.ValidateSecret("client1", "wrong") {
		t.Error("ValidateSecret should fail for wrong secret")
	}
	if !r.ValidateRedirectURI("client1", "http://localhost/cb") {
		t.Error("ValidateRedirectURI should pass for allowed URI")
	}
	if r.ValidateRedirectURI("client1", "http://evil.com/cb") {
		t.Error("ValidateRedirectURI should fail for disallowed URI")
	}
	if !r.ValidateScope("client1", "openid profile") {
		t.Error("ValidateScope should pass for allowed scopes")
	}
	if r.ValidateScope("client1", "openid admin") {
		t.Error("ValidateScope should fail for disallowed scope")
	}
	if !r.IsConfidential("client1") {
		t.Error("client1 should be confidential")
	}
	if r.IsConfidential("unknown") {
		t.Error("unknown client should not be confidential")
	}
	if !r.ValidateSecret("unknown", "anything") {
		t.Error("unknown client should allow any secret (public)")
	}
	if !r.ValidateRedirectURI("unknown", "http://any/cb") {
		t.Error("unknown client should allow any redirect_uri")
	}
}

func TestLoadFromEnv(t *testing.T) {
	r := NewRegistry()
	json := `{"env-client":{"client_secret":"env-secret","redirect_uris":["http://localhost:3000/cb"],"allowed_scopes":["openid"]}}`
	os.Setenv("CLIENT_REGISTRY", json)
	defer os.Unsetenv("CLIENT_REGISTRY")
	if err := r.LoadFromEnv(); err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if !r.ValidateSecret("env-client", "env-secret") {
		t.Error("env-client secret should work")
	}
	if !r.ValidateRedirectURI("env-client", "http://localhost:3000/cb") {
		t.Error("env-client redirect_uri should work")
	}
}
