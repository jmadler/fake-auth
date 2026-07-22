package webauthn

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jmadler/auth2/internal/store"
)

// Handler provides WebAuthn registration and assertion HTTP handlers.
type Handler struct {
	WebAuthn  *webauthn.WebAuthn
	Store     store.Store
	IssuerURL string
	enabled   bool
}

// Config holds WebAuthn configuration.
type Config struct {
	Enabled     bool
	DisplayName string
	RPID        string   // defaults to host from IssuerURL
	RPOrigins   []string
}

// New creates a WebAuthn handler. If config.Enabled is false, all handlers return 404/disabled.
func New(cfg Config, st store.Store, issuerURL string) (*Handler, error) {
	if !cfg.Enabled {
		return &Handler{Store: st, IssuerURL: issuerURL}, nil
	}
	displayName := cfg.DisplayName
	if displayName == "" {
		displayName = "auth2"
	}
	rpID := cfg.RPID
	if rpID == "" && issuerURL != "" {
		if u, err := url.Parse(issuerURL); err == nil && u.Host != "" {
			rpID = u.Hostname()
			if rpID == "localhost" {
				rpID = "localhost"
			}
		}
	}
	if rpID == "" {
		rpID = "localhost"
	}
	origins := cfg.RPOrigins
	if len(origins) == 0 && issuerURL != "" {
		origins = []string{strings.TrimSuffix(issuerURL, "/")}
	}
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: displayName,
		RPID:          rpID,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, err
	}
	return &Handler{WebAuthn: w, Store: st, IssuerURL: issuerURL, enabled: true}, nil
}

// webAuthnUser implements webauthn.User for store.User. Credentials are pre-loaded.
type webAuthnUser struct {
	user        *store.User
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.user.Email
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.Email
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func storeCredentialToWebAuthn(c *store.WebAuthnCredential) *webauthn.Credential {
	if c == nil || len(c.CredentialID) == 0 || len(c.PublicKey) == 0 {
		return nil
	}
	var transports []protocol.AuthenticatorTransport
	if c.Transports != "" && c.Transports != "[]" {
		_ = json.Unmarshal([]byte(c.Transports), &transports)
	}
	return &webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
	}
}

func (h *Handler) makeUser(ctx context.Context, u *store.User) (*webAuthnUser, error) {
	creds, err := h.Store.GetWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	var wc []webauthn.Credential
	for _, c := range creds {
		if w := storeCredentialToWebAuthn(&c); w != nil {
			wc = append(wc, *w)
		}
	}
	return &webAuthnUser{user: u, credentials: wc}, nil
}

func webauthnCredentialToStore(c *webauthn.Credential, userID string) *store.WebAuthnCredential {
	if c == nil {
		return nil
	}
	transports := "[]"
	if len(c.Transport) > 0 {
		b, _ := json.Marshal(c.Transport)
		transports = string(b)
	}
	id := "webauthn_" + uuid.New().String()
	return &store.WebAuthnCredential{
		ID:              id,
		UserID:          userID,
		CredentialID:    c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transports:      transports,
	}
}
