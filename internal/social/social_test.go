package social

import (
	"context"
	"testing"
)

func TestGetProvider_Nonexistent(t *testing.T) {
	p := GetProvider("nonexistent-provider-xyz")
	if p != nil {
		t.Error("GetProvider(nonexistent) should return nil")
	}
}

func TestRegisterAndGet(t *testing.T) {
	mp := &mockProvider{name: "mock"}
	RegisterProvider("mock_test", mp)
	defer func() {
		registryMu.Lock()
		delete(registry, "mock_test")
		registryMu.Unlock()
	}()

	p := GetProvider("mock_test")
	if p == nil {
		t.Fatal("GetProvider(mock_test) should return provider")
	}
	if p.Name() != "mock" {
		t.Errorf("Name = %q", p.Name())
	}
	url := p.AuthURL("state123", "http://localhost/cb")
	if url == "" {
		t.Error("AuthURL should not be empty")
	}
	if len(url) < 10 {
		t.Errorf("AuthURL too short: %q", url)
	}
}

func TestGetProvider_GoogleOAuth2Alias(t *testing.T) {
	// When google is registered, google-oauth2 normalizes to it
	mp := &mockProvider{name: "google"}
	RegisterProvider("google", mp)
	defer func() {
		registryMu.Lock()
		delete(registry, "google")
		registryMu.Unlock()
	}()

	p := GetProvider("google-oauth2")
	if p == nil {
		t.Fatal("google-oauth2 should resolve to google")
	}
	if p.Name() != "google" {
		t.Errorf("Name = %q", p.Name())
	}
}

type mockProvider struct {
	name string
}

func (m *mockProvider) Name() string { return m.name }

func (m *mockProvider) AuthURL(state, redirectURI string) string {
	return "https://example.com/auth?state=" + state
}

func (m *mockProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*UserInfo, error) {
	return nil, nil
}
