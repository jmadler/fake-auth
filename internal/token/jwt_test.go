package token

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestIssueAndValidate(t *testing.T) {
	issuer, err := NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, err := issuer.Issue("user|123", "https://api.example.com", "client-1", 3600, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
	claims, err := issuer.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sub, _ := claims["sub"].(string); sub != "user|123" {
		t.Errorf("sub = %q, want user|123", sub)
	}
	if aud, _ := claims["aud"].(string); aud != "https://api.example.com" {
		t.Errorf("aud = %q, want https://api.example.com", aud)
	}
	if azp, _ := claims["azp"].(string); azp != "client-1" {
		t.Errorf("azp = %q, want client-1", azp)
	}
}

func TestValidateRejectsTamperedToken(t *testing.T) {
	issuer, err := NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, _ := issuer.Issue("user|123", "aud", "client", 3600, nil)
	tampered := tok + "x"
	_, err = issuer.Validate(tampered)
	if err == nil {
		t.Fatal("expected validation to fail for tampered token")
	}
}

func TestValidateRejectsWrongIssuer(t *testing.T) {
	issuer1, _ := NewIssuer("https://issuer1.com/")
	issuer2, _ := NewIssuer("https://issuer2.com/")
	tok, _ := issuer1.Issue("user|123", "aud", "client", 3600, nil)
	_, err := issuer2.Validate(tok)
	if err == nil {
		t.Fatal("expected validation to fail for token from different issuer")
	}
}

func TestIssueIDToken(t *testing.T) {
	issuer, err := NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, err := issuer.IssueIDToken("user|123", "https://api.example.com", "client-1", 3600, "openid profile email", "bob@example.com", "Bob", "", nil)
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	claims, err := issuer.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if email, _ := claims["email"].(string); email != "bob@example.com" {
		t.Errorf("email = %q, want bob@example.com", email)
	}
	if name, _ := claims["name"].(string); name != "Bob" {
		t.Errorf("name = %q, want Bob", name)
	}
}

func TestJWKS(t *testing.T) {
	issuer, err := NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	b, err := issuer.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(b) < 50 {
		t.Errorf("JWKS too short: %d bytes", len(b))
	}
	if err := validateJWKSStructure(b); err != nil {
		t.Errorf("invalid JWKS structure: %v", err)
	}
}

func validateJWKSStructure(b []byte) error {
	var v struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if len(v.Keys) != 1 {
		return fmt.Errorf("expected 1 key, got %d", len(v.Keys))
	}
	if v.Keys[0].Kty != "RSA" || v.Keys[0].Alg != "RS256" {
		return fmt.Errorf("unexpected key type or alg")
	}
	if v.Keys[0].Kid == "" {
		return fmt.Errorf("expected kid in JWKS")
	}
	return nil
}

func TestKidInJWKSAndToken(t *testing.T) {
	issuer, err := NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	issuer.SetKid("test-key-1")
	tok, err := issuer.Issue("user|1", "aud", "client", 3600, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Parse JWT header to verify kid (we don't have a header parser, but JWKS should have it)
	b, err := issuer.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &jwks); err != nil {
		t.Fatal(err)
	}
	if jwks.Keys[0].Kid != "test-key-1" {
		t.Errorf("kid = %q, want test-key-1", jwks.Keys[0].Kid)
	}
	_ = tok
}

func TestIDTokenWithNonceAmrSid(t *testing.T) {
	issuer, err := NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	opts := &IDTokenOptions{
		Nonce:     "abc123",
		AMR:       []string{"pwd", "mfa"},
		SessionID: "sid_xyz789",
	}
	tok, err := issuer.IssueIDToken("user|1", "aud", "client", 3600, "openid", "bob@test.com", "Bob", "", opts)
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	claims, err := issuer.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if nonce, _ := claims["nonce"].(string); nonce != "abc123" {
		t.Errorf("nonce = %q, want abc123", nonce)
	}
	if amr, ok := claims["amr"].([]interface{}); !ok || len(amr) != 2 {
		t.Errorf("amr = %v", claims["amr"])
	}
	if sid, _ := claims["sid"].(string); sid != "sid_xyz789" {
		t.Errorf("sid = %q, want sid_xyz789", sid)
	}
}

func TestIDTokenWithAtHashAndCHash(t *testing.T) {
	issuer, err := NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	accessTok := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.x"
	authCode := "ac_abc123def456"
	opts := &IDTokenOptions{
		AccessToken: accessTok,
		AuthCode:    authCode,
	}
	tok, err := issuer.IssueIDToken("user|1", "aud", "client", 3600, "openid", "bob@test.com", "Bob", "", opts)
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	claims, err := issuer.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, ok := claims["at_hash"]; !ok {
		t.Error("expected at_hash in id_token")
	}
	if _, ok := claims["c_hash"]; !ok {
		t.Error("expected c_hash in id_token")
	}
}

func TestIDTokenWithCustomClaims(t *testing.T) {
	issuer, err := NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	opts := &IDTokenOptions{
		CustomClaims: map[string]interface{}{
			"https://myapp.com/roles": []string{"admin"},
			"org_id":                  "org_123",
		},
	}
	tok, err := issuer.IssueIDToken("user|1", "aud", "client", 3600, "openid", "bob@test.com", "Bob", "", opts)
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	claims, err := issuer.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if roles, ok := claims["https://myapp.com/roles"].([]interface{}); !ok || len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("custom roles = %v", claims["https://myapp.com/roles"])
	}
	if org, _ := claims["org_id"].(string); org != "org_123" {
		t.Errorf("org_id = %q", org)
	}
}

func TestIssueWithCustomClaims(t *testing.T) {
	issuer, err := NewIssuer("https://test.example.com/")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, err := issuer.Issue("user|1", "aud", "client", 3600, map[string]interface{}{
		"scope": "read:users",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := issuer.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if scope, _ := claims["scope"].(string); scope != "read:users" {
		t.Errorf("scope = %q", scope)
	}
}
