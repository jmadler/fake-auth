package enterprise

import (
	"testing"
)

func TestNewProvider_Nil(t *testing.T) {
	p := NewProvider(nil)
	if p != nil {
		t.Error("NewProvider(nil) should return nil")
	}
}

func TestNewProvider_Name(t *testing.T) {
	p := NewProvider(&OIDCConnection{
		Name:      "okta",
		IssuerURL: "https://dev-123.okta.com",
		ClientID:  "cid",
	})
	if p == nil {
		t.Fatal("NewProvider should return provider")
	}
	if got := p.Name(); got != "okta" {
		t.Errorf("Name() = %q, want okta", got)
	}
}

func TestNewProvider_WithConnection(t *testing.T) {
	p := NewProvider(&OIDCConnection{
		Name:         "azure",
		IssuerURL:    "https://login.microsoftonline.com/tenant/v2.0",
		ClientID:     "cid",
		ClientSecret: "secret",
		Scope:        "openid email",
	})
	if p == nil {
		t.Fatal("NewProvider should return provider")
	}
	if p.Name() != "azure" {
		t.Errorf("Name = %q", p.Name())
	}
	// AuthURL triggers OIDC discovery HTTP request - skip in unit test
	// Use integration test with httptest.Server for full AuthURL test
}

func TestNewProvider_WithScope(t *testing.T) {
	// NewProvider uses default scope when empty
	p := NewProvider(&OIDCConnection{
		Name:     "okta",
		Scope:     "openid custom",
		IssuerURL: "https://okta.com",
	})
	if p == nil {
		t.Fatal("NewProvider should return provider")
	}
	// Scope is stored for use in AuthURL
	_ = p.Name()
}
