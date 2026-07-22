package enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/oauth2"
)

// UserInfo contains identity from an enterprise OIDC IdP.
type UserInfo struct {
	Email string
	Name  string
	Sub   string
}

// Provider implements OIDC login for enterprise IdPs (Okta, Azure AD, etc.).
type Provider interface {
	Name() string
	AuthURL(state, redirectURI string) string
	ExchangeCode(ctx context.Context, code, redirectURI string) (*UserInfo, error)
}

// oidcProvider implements Provider using OIDC discovery.
type oidcProvider struct {
	name         string
	issuerURL    string
	clientID     string
	clientSecret string
	scope        string
	domainHint   string
	config       *oauth2.Config
	configOnce   sync.Once
	configErr    error
}

// OIDCConnection holds the config for an OIDC enterprise connection.
type OIDCConnection struct {
	Name         string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scope        string
	DomainHint   string
}

// NewProvider creates an OIDC enterprise provider from connection config.
func NewProvider(conn *OIDCConnection) Provider {
	if conn == nil {
		return nil
	}
	scope := conn.Scope
	if scope == "" {
		scope = "openid email profile"
	}
	return &oidcProvider{
		name:         conn.Name,
		issuerURL:    strings.TrimSuffix(conn.IssuerURL, "/"),
		clientID:     conn.ClientID,
		clientSecret: conn.ClientSecret,
		scope:        scope,
		domainHint:   conn.DomainHint,
	}
}

func (p *oidcProvider) Name() string { return p.name }

func (p *oidcProvider) ensureConfig(ctx context.Context, redirectURI string) error {
	p.configOnce.Do(func() {
		discoURL := p.issuerURL + "/.well-known/openid-configuration"
		req, err := http.NewRequestWithContext(ctx, "GET", discoURL, nil)
		if err != nil {
			p.configErr = err
			return
		}
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			p.configErr = fmt.Errorf("fetch OIDC discovery: %w", err)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			p.configErr = err
			return
		}
		if resp.StatusCode != http.StatusOK {
			p.configErr = fmt.Errorf("OIDC discovery status %d: %s", resp.StatusCode, string(body))
			return
		}
		var disco struct {
			AuthURL   string `json:"authorization_endpoint"`
			TokenURL  string `json:"token_endpoint"`
			UserInfo  string `json:"userinfo_endpoint"`
			Issuer    string `json:"issuer"`
		}
		if err := json.Unmarshal(body, &disco); err != nil {
			p.configErr = fmt.Errorf("parse OIDC discovery: %w", err)
			return
		}
		if disco.AuthURL == "" || disco.TokenURL == "" {
			p.configErr = fmt.Errorf("OIDC discovery missing auth/token endpoints")
			return
		}
		userInfoURL := disco.UserInfo
		if userInfoURL == "" {
			userInfoURL = p.issuerURL + "/userinfo"
		}
		p.config = &oauth2.Config{
			ClientID:     p.clientID,
			ClientSecret: p.clientSecret,
			RedirectURL:  redirectURI,
			Scopes:       strings.Split(p.scope, " "),
			Endpoint: oauth2.Endpoint{
				AuthURL:  disco.AuthURL,
				TokenURL: disco.TokenURL,
			},
		}
		// Store userinfo URL for later - we'll need it in ExchangeCode
		// For now we use the discovery; ExchangeCode will use token endpoint from config
		_ = userInfoURL
	})
	return p.configErr
}

func (p *oidcProvider) AuthURL(state, redirectURI string) string {
	ctx := context.Background()
	if err := p.ensureConfig(ctx, redirectURI); err != nil {
		return ""
	}
	cfg := *p.config
	cfg.RedirectURL = redirectURI
	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}
	if p.domainHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("domain_hint", p.domainHint))
	}
	return cfg.AuthCodeURL(state, opts...)
}

func (p *oidcProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*UserInfo, error) {
	if err := p.ensureConfig(ctx, redirectURI); err != nil {
		return nil, err
	}
	p.config.RedirectURL = redirectURI
	tok, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	userInfoURL, err := GetUserInfoURL(ctx, p.issuerURL)
	if err != nil {
		userInfoURL = p.issuerURL + "/userinfo"
	}
	uReq, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	uResp, err := p.config.Client(ctx, tok).Do(uReq)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	defer uResp.Body.Close()
	body, err := io.ReadAll(uResp.Body)
	if err != nil {
		return nil, err
	}
	if uResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo status %d: %s", uResp.StatusCode, string(body))
	}
	var v struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		PreferredUser string `json:"preferred_username"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("parse userinfo: %w", err)
	}
	email := v.Email
	if email == "" {
		email = v.PreferredUser
	}
	if email == "" {
		email = v.Sub
	}
	name := v.Name
	if name == "" && (v.GivenName != "" || v.FamilyName != "") {
		name = strings.TrimSpace(v.GivenName + " " + v.FamilyName)
	}
	return &UserInfo{Email: email, Name: name, Sub: v.Sub}, nil
}

// GetUserInfoURL fetches userinfo endpoint from OIDC discovery.
func GetUserInfoURL(ctx context.Context, issuerURL string) (string, error) {
	discoURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", discoURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var disco struct {
		UserInfo string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil {
		return "", err
	}
	if disco.UserInfo == "" {
		s, _ := url.JoinPath(strings.TrimSuffix(issuerURL, "/"), "userinfo")
		return s, nil
	}
	return disco.UserInfo, nil
}
