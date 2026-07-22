package store

import (
	"context"
	"time"
)

// Store defines the full persistence interface implemented by SQLiteStore and PostgresStore.
type Store interface {
	UserStore
	Close() error
	Ping(ctx context.Context) error

	// User management
	CreateUser(ctx context.Context, u *User, password string) error
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)
	GetUserPermissions(ctx context.Context, userID string) ([]Permission, error)
	ListRoles(ctx context.Context) ([]Role, error)
	AssignRoleToUser(ctx context.Context, userID, roleID string) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID string) error
	ListUsers(ctx context.Context, opts ListUsersOpts) ([]User, int, error)
	UpdateUser(ctx context.Context, id string, updates map[string]interface{}) error
	UpdateEmailVerified(ctx context.Context, userID string, verified bool) error
	UpdatePassword(ctx context.Context, userID string, newPassword string) error
	DeleteUser(ctx context.Context, id string) error

	// Roles
	GetRoleByID(ctx context.Context, id string) (*Role, error)
	CreateRole(ctx context.Context, r *Role) error
	UpdateRole(ctx context.Context, id string, name, description string) error
	DeleteRole(ctx context.Context, id string) error

	// Clients & Connections
	ListClients(ctx context.Context) ([]Client, error)
	GetClientByID(ctx context.Context, id string) (*Client, error)
	UpdateClient(ctx context.Context, id string, updates map[string]interface{}) error
	ListConnections(ctx context.Context) ([]Connection, error)
	GetConnectionByID(ctx context.Context, id string) (*Connection, error)

	// User blocks
	BlockUser(ctx context.Context, userID string) error
	UnblockUser(ctx context.Context, userID string) error
	IsUserBlocked(ctx context.Context, userID string) (bool, error)

	// Password reset tokens (prefix: prt_)
	CreatePasswordResetToken(ctx context.Context, userID string, expiresAt time.Time) (string, error)
	ValidatePasswordResetToken(ctx context.Context, token string) (userID string, ok bool)
	ConsumePasswordResetToken(ctx context.Context, token string) (userID string, ok bool)

	// Magic link passwordless tokens (prefix: magic_)
	CreateMagicLinkToken(ctx context.Context, data *MagicLinkTokenData) (token string, err error)
	ConsumeMagicLinkToken(ctx context.Context, token string) (*MagicLinkTokenData, bool)

	// SMS OTP passwordless tokens (prefix: sms_)
	CreateSMSOTPToken(ctx context.Context, data *SMSOTPTokenData) (token string, err error)
	ConsumeSMSOTPToken(ctx context.Context, token, code string) (*SMSOTPTokenData, bool)

	// Adaptive MFA: known IPs per user
	AddKnownIP(ctx context.Context, userID, ip string) error
	IsIPKnownForUser(ctx context.Context, userID, ip string) (bool, error)

	// Brute-force lockout (login attempts)
	RecordFailedLogin(ctx context.Context, identifier string) error
	ClearFailedLogins(ctx context.Context, identifier string) error
	IsLockedOut(ctx context.Context, identifier string) (lockedUntil time.Time, ok bool)

	// Audit logs
	AppendLog(ctx context.Context, eventType, userID, clientID, payload string) error
	ListLogs(ctx context.Context, limit int) ([]AuditLog, error)
	DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)

	// User export (bulk export for migration)
	ListUsersExport(ctx context.Context, page, perPage int) ([]ExportUser, int, error)

	// MFA enrollment
	GetMFAEnrollment(ctx context.Context, userID string) (*MFAEnrollment, error)
	SetMFAEnrollment(ctx context.Context, userID, totpSecret string, backupCodeHashes []string) error
	ConsumeBackupCode(ctx context.Context, userID, code string) (consumed bool, err error)

	// Social / federation identity linking
	GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*User, error)
	LinkUserIdentity(ctx context.Context, userID, provider, providerUserID string) error

	// SAML IdP: Service Providers
	CreateSAMLServiceProvider(ctx context.Context, sp *SAMLServiceProvider) error
	GetSAMLServiceProviderByEntityID(ctx context.Context, entityID string) (*SAMLServiceProvider, error)
	ListSAMLServiceProviders(ctx context.Context) ([]SAMLServiceProvider, error)

	// OIDC Enterprise connections (generic: Okta, Azure AD, etc.)
	CreateOIDCEnterpriseConnection(ctx context.Context, ec *OIDCEnterpriseConnection) error
	GetOIDCEnterpriseConnectionByName(ctx context.Context, name string) (*OIDCEnterpriseConnection, error)
	ListOIDCEnterpriseConnections(ctx context.Context) ([]OIDCEnterpriseConnection, error)

	// WebAuthn credentials (passkeys)
	GetWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error

	// Organizations (Auth0 B2B)
	CreateOrganization(ctx context.Context, org *Organization) error
	GetOrganization(ctx context.Context, id string) (*Organization, error)
	ListOrganizations(ctx context.Context) ([]Organization, error)
	UpdateOrganization(ctx context.Context, id string, updates map[string]interface{}) error
	DeleteOrganization(ctx context.Context, id string) error
	AddOrgMember(ctx context.Context, orgID, userID, role string) error
	RemoveOrgMember(ctx context.Context, orgID, userID string) error
	ListOrgMembers(ctx context.Context, orgID string) ([]OrgMember, error)
	IsOrgMember(ctx context.Context, orgID, userID string) (bool, error)
	SetOrgConnection(ctx context.Context, orgID, connectionID string) error
	ListOrgConnections(ctx context.Context, orgID string) ([]string, error)
	RemoveOrgConnection(ctx context.Context, orgID, connectionID string) error
	CreateEnterpriseConnection(ctx context.Context, ec *EnterpriseConnection) error
	GetEnterpriseConnection(ctx context.Context, id string) (*EnterpriseConnection, error)
	ListEnterpriseConnections(ctx context.Context, orgID string) ([]EnterpriseConnection, error)
	GetEnterpriseConnectionByDomain(ctx context.Context, domain string) (*EnterpriseConnection, error)
	CreateInvitation(ctx context.Context, inv *Invitation) (string, error)
	GetInvitationByToken(ctx context.Context, token string) (*Invitation, error)
	ConsumeInvitation(ctx context.Context, token string) (*Invitation, bool)

	// CIBA (Client Initiated Backchannel Authentication)
	SaveCIBARequest(ctx context.Context, req *CIBARequest) error
	GetCIBARequest(ctx context.Context, authReqID string) (*CIBARequest, error)
	UpdateCIBARequestStatus(ctx context.Context, authReqID, status, userID string) error

	// Token Vault (for AI agents)
	SaveTokenVaultEntry(ctx context.Context, entry *TokenVaultEntry) (string, error)
	GetTokenVaultEntry(ctx context.Context, name, userID string) (*TokenVaultEntry, error)
	GetTokenVaultEntryByID(ctx context.Context, id string) (*TokenVaultEntry, error)
}

// WebAuthnCredential stores a passkey credential for a user.
type WebAuthnCredential struct {
	ID              string
	UserID          string
	CredentialID    []byte // base64url or raw bytes stored
	PublicKey       []byte
	AttestationType string
	Transports      string // JSON array of transport names
	CreatedAt       time.Time
}

// MFAEnrollment holds TOTP secret and backup code hashes for a user.
type MFAEnrollment struct {
	UserID          string
	TOTPSecret      string
	BackupCodeHashes []string
}

type User struct {
	ID             string
	Email          string
	PhoneNumber    string
	PasswordHash   string
	DisplayName    string
	EmailVerified  bool
	AppMetadata    map[string]interface{}
	UserMetadata   map[string]interface{}
	OrganizationID int
	EnterpriseID   int
	Role           string
}

type Role struct {
	ID          string
	Name        string
	Description string
}

type Permission struct {
	ID                        string
	Name                      string
	ResourceServerIdentifier  string
	Description               string
}

type UserStore interface {
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
	GetByPhone(ctx context.Context, phone string) (*User, error)
	Create(ctx context.Context, u *User) error
	UpdateAppMetadata(ctx context.Context, id string, meta map[string]interface{}) error
	VerifyPassword(hash, password string) bool
}

type ListUsersOpts struct {
	Page    int
	PerPage int
	Query   string // simple search: email or display_name contains
}

// ExportUser holds user data for export (no passwords).
type ExportUser struct {
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email"`
	Name         string                 `json:"name"`
	EmailVerified bool                  `json:"email_verified"`
	CreatedAt    time.Time              `json:"created_at"`
	UserMetadata map[string]interface{} `json:"user_metadata,omitempty"`
	AppMetadata  map[string]interface{} `json:"app_metadata,omitempty"`
}

type Client struct {
	ID             string
	Name           string
	AppType        string
	Callbacks      []string
	AllowedOrigins []string
}

type Connection struct {
	ID       string
	Name     string
	Strategy string
}

type AuditLog struct {
	ID        int64
	EventType string
	UserID    string
	ClientID  string
	Payload   string
}

// MagicLinkTokenData holds magic link token payload for passwordless login.
type MagicLinkTokenData struct {
	Email        string
	ClientID     string
	RedirectURI  string
	State        string
	ResponseType string
	Scope        string
	Audience     string
}

// SMSOTPTokenData holds SMS OTP token payload for passwordless login.
type SMSOTPTokenData struct {
	Phone        string
	Code         string
	ClientID     string
	RedirectURI  string
	State        string
	ResponseType string
	Scope        string
	Audience     string
}

// SAMLServiceProvider is a Service Provider that auth2 acts as IdP for.
type SAMLServiceProvider struct {
	ID           string
	EntityID     string
	ACSURL       string
	Certificate  string
	MetadataURL  string
	CreatedAt    time.Time
}

// OIDCEnterpriseConnection is a generic OIDC IdP connector (Okta, Azure AD, etc.).
type OIDCEnterpriseConnection struct {
	ID           string
	Name         string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scope        string
	DomainHint   string
	CreatedAt    time.Time
}

// Organization represents an Auth0 B2B organization.
type Organization struct {
	ID          string
	Name        string
	DisplayName string
	Metadata    map[string]interface{}
	CreatedAt   time.Time
}

// OrgMember represents membership in an organization.
type OrgMember struct {
	OrgID  string
	UserID string
	Role   string
}

// EnterpriseConnection is a self-service OIDC SSO connection (domain_hint, issuer_url).
type EnterpriseConnection struct {
	ID           string
	OrgID        string
	Name         string
	DomainHint   string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	CreatedAt    time.Time
}

// Invitation for org membership.
type Invitation struct {
	ID        string
	OrgID     string
	Email     string
	Role      string
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// CIBARequest represents a CIBA authentication request.
type CIBARequest struct {
	AuthReqID string
	ClientID  string
	LoginHint string
	Scope     string
	Audience  string
	Status    string // pending, approved, denied, expired
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// TokenVaultEntry stores an encrypted access token by name for AI agents.
type TokenVaultEntry struct {
	ID                   string
	Name                 string
	UserID               string
	AccessTokenEncrypted string
	Metadata             string
	CreatedAt            time.Time
}
