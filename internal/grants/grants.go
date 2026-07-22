package grants

import "time"

// GrantStore manages auth codes, refresh tokens, device codes, and MFA pending challenges.
// Implementations may be in-memory (single-instance) or Redis (multi-instance).
type GrantStore interface {
	SaveCode(code string, ac *AuthCode)
	ConsumeCode(code string) (*AuthCode, bool)
	SaveRefreshToken(token string, rg *RefreshGrant)
	ConsumeRefreshToken(token string) (*RefreshGrant, bool)
	RevokeRefreshToken(token string) bool
	SaveDeviceCode(deviceCode, userCode string, dc *DeviceCode)
	GetDeviceCode(deviceCode string) (*DeviceCode, bool)
	AuthorizeDeviceCode(userCode, userID string) bool
	DenyDeviceCode(userCode string) bool
	ConsumeDeviceCode(deviceCode string) (*DeviceCode, bool)

	// MFA pending: password verified but MFA code not yet submitted
	SaveMFAPending(challengeID string, pending *MFAPending)
	GetMFAPending(challengeID string) (*MFAPending, bool)
	ConsumeMFAPending(challengeID string) (*MFAPending, bool)

	// Social OAuth state: stores redirect params during provider OAuth flow
	SaveSocialState(state string, data *SocialState)
	GetSocialState(state string) (*SocialState, bool)
	ConsumeSocialState(state string) (*SocialState, bool)

	// WebAuthn session: stores SessionData between begin and finish (registration/assertion)
	SaveWebAuthnSession(sessionID string, data []byte)
	GetWebAuthnSession(sessionID string) ([]byte, bool)
	ConsumeWebAuthnSession(sessionID string) ([]byte, bool)
}

// SocialState holds OAuth params during social login redirect.
type SocialState struct {
	RedirectURI         string
	ClientID            string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Audience            string
	ResponseType        string
	Connection          string
	ExpiresAt           time.Time
}

// MFAPending holds auth context when password is verified but MFA challenge is required.
type MFAPending struct {
	UserID    string
	ClientID  string
	Scope     string
	Audience  string
	ClientIP  string // for adaptive MFA: add to known IPs on success
	ExpiresAt time.Time
}
