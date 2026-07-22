package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// UserInfo contains identity from a social provider.
type UserInfo struct {
	Email string // Primary email
	Name  string // Display name
	Sub   string // Provider's user ID (stable, unique)
}

// Provider implements OAuth2 login for a social identity provider.
type Provider interface {
	Name() string
	AuthURL(state, redirectURI string) string
	ExchangeCode(ctx context.Context, code, redirectURI string) (*UserInfo, error)
}

// googleProvider implements Provider for Google OAuth2.
type googleProvider struct {
	cfg *oauth2.Config
}

func (p *googleProvider) Name() string { return "google" }

func (p *googleProvider) AuthURL(state, redirectURI string) string {
	cfg := *p.cfg
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam("prompt", "consent"))
}

func (p *googleProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*UserInfo, error) {
	p.cfg.RedirectURL = redirectURI
	tok, err := p.cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("google token exchange: %w", err)
	}
	client := p.cfg.Client(ctx, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo status %d: %s", resp.StatusCode, string(body))
	}
	var v struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name         string `json:"name"`
		GivenName    string `json:"given_name"`
		FamilyName   string `json:"family_name"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("google userinfo parse: %w", err)
	}
	email := v.Email
	if email == "" {
		return nil, fmt.Errorf("google: no email in userinfo")
	}
	name := v.Name
	if name == "" && (v.GivenName != "" || v.FamilyName != "") {
		name = strings.TrimSpace(v.GivenName + " " + v.FamilyName)
	}
	return &UserInfo{Email: email, Name: name, Sub: v.Sub}, nil
}

// githubProvider implements Provider for GitHub OAuth2.
type githubProvider struct {
	cfg *oauth2.Config
}

var githubEndpoint = oauth2.Endpoint{
	AuthURL:   "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_token",
}

func (p *githubProvider) Name() string { return "github" }

func (p *githubProvider) AuthURL(state, redirectURI string) string {
	cfg := *p.cfg
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (p *githubProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*UserInfo, error) {
	p.cfg.RedirectURL = redirectURI
	tok, err := p.cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("github token exchange: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github user: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github user status %d: %s", resp.StatusCode, string(body))
	}
	var v struct {
		ID    int    `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("github user parse: %w", err)
	}
	sub := fmt.Sprintf("%d", v.ID)
	email := v.Email
	if email == "" {
		// GitHub often hides email; try emails endpoint
		req2, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
		req2.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req2.Header.Set("Accept", "application/json")
		r2, err := client.Do(req2)
		if err == nil && r2.StatusCode == http.StatusOK {
			defer r2.Body.Close()
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if json.NewDecoder(r2.Body).Decode(&emails) == nil {
				for _, e := range emails {
					if e.Primary && e.Verified {
						email = e.Email
						break
					}
				}
				if email == "" && len(emails) > 0 {
					email = emails[0].Email
				}
			}
		}
	}
	if email == "" {
		email = v.Login + "@users.noreply.github.com"
	}
	name := v.Name
	if name == "" {
		name = v.Login
	}
	return &UserInfo{Email: email, Name: name, Sub: sub}, nil
}

// Registry holds social providers by name.
var (
	registry   = make(map[string]Provider)
	registryMu sync.RWMutex
)

// RegisterProvider registers a provider by name. Names "google", "google-oauth2", "github" are used.
func RegisterProvider(name string, p Provider) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = p
}

// GetProvider returns the provider for the given name, or nil.
// Supports "google", "google-oauth2", "github" (Auth0-style connection names).
func GetProvider(name string) Provider {
	registryMu.RLock()
	defer registryMu.RUnlock()
	if p, ok := registry[name]; ok {
		return p
	}
	// Normalize: google-oauth2 -> google
	if name == "google-oauth2" {
		return registry["google"]
	}
	return nil
}

func init() {
	// Google
	if id := os.Getenv("GOOGLE_CLIENT_ID"); id != "" {
		secret := os.Getenv("GOOGLE_CLIENT_SECRET")
		gp := &googleProvider{
			cfg: &oauth2.Config{
				ClientID:     id,
				ClientSecret: secret,
				RedirectURL:  "", // Set per-request from issuer
				Scopes:       []string{"openid", "email", "profile"},
				Endpoint:     google.Endpoint,
			},
		}
		RegisterProvider("google", gp)
		RegisterProvider("google-oauth2", gp)
	}
	// GitHub
	if id := os.Getenv("GITHUB_CLIENT_ID"); id != "" {
		secret := os.Getenv("GITHUB_CLIENT_SECRET")
		RegisterProvider("github", &githubProvider{
			cfg: &oauth2.Config{
				ClientID:     id,
				ClientSecret: secret,
				RedirectURL:  "",
				Scopes:       []string{"user:email", "read:user"},
				Endpoint:     githubEndpoint,
			},
		})
	}
}
