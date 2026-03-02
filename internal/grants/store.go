package grants

import (
	"strings"
	"sync"
	"time"
)

type AuthCode struct {
	UserID              string
	ClientID            string
	RedirectURI         string
	Scope               string
	Audience            string
	Nonce               string
	SessionID           string
	CodeChallenge       string // PKCE
	CodeChallengeMethod string // S256 or plain
	ExpiresAt           time.Time
}

type RefreshGrant struct {
	UserID     string
	ClientID   string
	Scope      string
	Audience   string
	SessionID  string
	ExpiresAt  time.Time
}

// DeviceCode represents a device authorization grant.
type DeviceCode struct {
	DeviceCode      string
	UserCode        string
	UserID          string
	ClientID        string
	Scope           string
	Audience        string
	ExpiresAt       time.Time
	Interval        int  // seconds between polls
	UserAuthorized  bool // set when user completes auth
	AccessDenied    bool
	Expired         bool
}

type Store struct {
	mu          sync.RWMutex
	codes       map[string]*AuthCode
	refresh     map[string]*RefreshGrant
	devices     map[string]*DeviceCode    // device_code -> DeviceCode
	userCodes   map[string]string         // user_code (uppercase) -> device_code
	codeTTL     time.Duration
	refreshTTL  time.Duration
	deviceTTL   time.Duration
}

// NewStore creates a grant store. Optional third arg is device code TTL for testing.
func NewStore(codeTTL, refreshTTL time.Duration, deviceTTL ...time.Duration) *Store {
	if codeTTL <= 0 {
		codeTTL = 5 * time.Minute
	}
	if refreshTTL <= 0 {
		refreshTTL = 30 * 24 * time.Hour // 30 days
	}
	dt := 15 * time.Minute
	if len(deviceTTL) > 0 && deviceTTL[0] > 0 {
		dt = deviceTTL[0]
	}
	return &Store{
		codes:      make(map[string]*AuthCode),
		refresh:    make(map[string]*RefreshGrant),
		devices:    make(map[string]*DeviceCode),
		userCodes:  make(map[string]string),
		codeTTL:    codeTTL,
		refreshTTL: refreshTTL,
		deviceTTL:  dt,
	}
}

func (s *Store) SaveCode(code string, ac *AuthCode) {
	ac.ExpiresAt = time.Now().Add(s.codeTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanExpiredCodesLocked()
	s.codes[code] = ac
}

func (s *Store) ConsumeCode(code string) (*AuthCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok || time.Now().After(ac.ExpiresAt) {
		if ok {
			delete(s.codes, code)
		}
		return nil, false
	}
	delete(s.codes, code)
	return ac, true
}

func (s *Store) SaveRefreshToken(token string, rg *RefreshGrant) {
	rg.ExpiresAt = time.Now().Add(s.refreshTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanExpiredRefreshLocked()
	s.refresh[token] = rg
}

func (s *Store) ConsumeRefreshToken(token string) (*RefreshGrant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rg, ok := s.refresh[token]
	if !ok || time.Now().After(rg.ExpiresAt) {
		if ok {
			delete(s.refresh, token)
		}
		return nil, false
	}
	delete(s.refresh, token)
	return rg, true
}

// RevokeRefreshToken removes a refresh token (for revocation endpoint).
func (s *Store) RevokeRefreshToken(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.refresh[token]
	if ok {
		delete(s.refresh, token)
	}
	return ok
}

func (s *Store) cleanExpiredCodesLocked() {
	now := time.Now()
	for k, v := range s.codes {
		if now.After(v.ExpiresAt) {
			delete(s.codes, k)
		}
	}
}

func (s *Store) cleanExpiredRefreshLocked() {
	now := time.Now()
	for k, v := range s.refresh {
		if now.After(v.ExpiresAt) {
			delete(s.refresh, k)
		}
	}
}

// SaveDeviceCode stores a device authorization. userCode is shown to user (e.g. "ABCD-EFGH").
func (s *Store) SaveDeviceCode(deviceCode, userCode string, dc *DeviceCode) {
	dc.ExpiresAt = time.Now().Add(s.deviceTTL)
	dc.Interval = 5
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanExpiredDevicesLocked()
	s.devices[deviceCode] = dc
	// normalize user code for lookup (uppercase, no hyphen)
	normalized := strings.ToUpper(strings.ReplaceAll(userCode, "-", ""))
	s.userCodes[normalized] = deviceCode
}

// GetDeviceCode returns the DeviceCode for a device_code. Does not consume it.
func (s *Store) GetDeviceCode(deviceCode string) (*DeviceCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanExpiredDevicesLocked()
	dc, ok := s.devices[deviceCode]
	if !ok || dc.Expired || time.Now().After(dc.ExpiresAt) {
		return nil, false
	}
	return dc, true
}

// AuthorizeDeviceCode marks the device code as user-authorized. Call before ConsumeDeviceCode.
func (s *Store) AuthorizeDeviceCode(userCode, userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized := strings.ToUpper(strings.ReplaceAll(userCode, "-", ""))
	deviceCode, ok := s.userCodes[normalized]
	if !ok {
		return false
	}
	dc, ok := s.devices[deviceCode]
	if !ok || dc.Expired || time.Now().After(dc.ExpiresAt) {
		return false
	}
	dc.UserAuthorized = true
	dc.UserID = userID
	return true
}

// DenyDeviceCode marks the device code as access_denied.
func (s *Store) DenyDeviceCode(userCode string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized := strings.ToUpper(strings.ReplaceAll(userCode, "-", ""))
	deviceCode, ok := s.userCodes[normalized]
	if !ok {
		return false
	}
	dc, ok := s.devices[deviceCode]
	if !ok {
		return false
	}
	dc.AccessDenied = true
	return true
}

// ConsumeDeviceCode consumes and removes the device code. Returns the grant info for token issuance.
func (s *Store) ConsumeDeviceCode(deviceCode string) (*DeviceCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.devices[deviceCode]
	if !ok || !dc.UserAuthorized || dc.Expired || time.Now().After(dc.ExpiresAt) {
		return nil, false
	}
	delete(s.devices, deviceCode)
	normalized := strings.ToUpper(strings.ReplaceAll(dc.UserCode, "-", ""))
	delete(s.userCodes, normalized)
	return dc, true
}

func (s *Store) cleanExpiredDevicesLocked() {
	now := time.Now()
	for k, v := range s.devices {
		if now.After(v.ExpiresAt) || v.Expired {
			delete(s.devices, k)
			normalized := strings.ToUpper(strings.ReplaceAll(v.UserCode, "-", ""))
			delete(s.userCodes, normalized)
		}
	}
}
