package webauthn

import (
	"testing"
)

func TestNew_Disabled(t *testing.T) {
	h, err := New(Config{Enabled: false}, nil, "https://auth.example.com")
	if err != nil {
		t.Fatalf("New disabled: %v", err)
	}
	if h == nil {
		t.Fatal("handler should not be nil")
	}
	if h.WebAuthn != nil {
		t.Error("WebAuthn should be nil when disabled")
	}
	if h.Store != nil {
		t.Error("Store should be nil when nil passed")
	}
	if h.IssuerURL != "https://auth.example.com" {
		t.Errorf("IssuerURL = %q", h.IssuerURL)
	}
}

func TestNew_WithStore(t *testing.T) {
	h, err := New(Config{Enabled: false}, nil, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h.IssuerURL != "" {
		t.Errorf("IssuerURL = %q", h.IssuerURL)
	}
}
