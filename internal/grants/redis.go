package grants

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	codeTTL         = 5 * time.Minute
	refreshTTL      = 30 * 24 * time.Hour
	deviceTTL       = 15 * time.Minute
	mfaTTL          = 5 * time.Minute
	socialStateTTL  = 10 * time.Minute

	keyPrefixAuthCode    = "grant:code:"
	keyPrefixRefresh     = "grant:refresh:"
	keyPrefixDevice      = "grant:device:"
	keyPrefixUserCode    = "grant:usercode:"
	keyPrefixMFAPending  = "grant:mfa:"
	keyPrefixSocialState   = "grant:social:"
	keyPrefixWebAuthnSess  = "grant:webauthn:"
	webauthnSessionTTL    = 5 * time.Minute
)

// RedisStore implements GrantStore using Redis with TTL.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore creates a Redis-backed grant store.
func NewRedisStore(redisURL string) (*RedisStore, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse REDIS_URL: %w", err)
	}
	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &RedisStore{client: client}, nil
}

// Client returns the Redis client for health checks and graceful shutdown.
func (s *RedisStore) Client() *redis.Client { return s.client }

// Close closes the Redis connection.
func (s *RedisStore) Close() error { return s.client.Close() }

func (s *RedisStore) SaveCode(code string, ac *AuthCode) {
	ac.ExpiresAt = time.Now().Add(codeTTL)
	b, _ := json.Marshal(ac)
	ctx := context.Background()
	s.client.Set(ctx, keyPrefixAuthCode+code, b, codeTTL)
}

func (s *RedisStore) ConsumeCode(code string) (*AuthCode, bool) {
	ctx := context.Background()
	key := keyPrefixAuthCode + code
	b, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	s.client.Del(ctx, key)
	var ac AuthCode
	if json.Unmarshal(b, &ac) != nil {
		return nil, false
	}
	if time.Now().After(ac.ExpiresAt) {
		return nil, false
	}
	return &ac, true
}

func (s *RedisStore) SaveRefreshToken(token string, rg *RefreshGrant) {
	rg.ExpiresAt = time.Now().Add(refreshTTL)
	b, _ := json.Marshal(rg)
	ctx := context.Background()
	s.client.Set(ctx, keyPrefixRefresh+token, b, refreshTTL)
}

func (s *RedisStore) ConsumeRefreshToken(token string) (*RefreshGrant, bool) {
	ctx := context.Background()
	key := keyPrefixRefresh + token
	b, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	s.client.Del(ctx, key)
	var rg RefreshGrant
	if json.Unmarshal(b, &rg) != nil {
		return nil, false
	}
	if time.Now().After(rg.ExpiresAt) {
		return nil, false
	}
	return &rg, true
}

func (s *RedisStore) RevokeRefreshToken(token string) bool {
	ctx := context.Background()
	n, err := s.client.Del(ctx, keyPrefixRefresh+token).Result()
	return err == nil && n > 0
}

func (s *RedisStore) SaveDeviceCode(deviceCode, userCode string, dc *DeviceCode) {
	dc.ExpiresAt = time.Now().Add(deviceTTL)
	dc.Interval = 5
	dc.UserCode = userCode
	b, _ := json.Marshal(dc)
	ctx := context.Background()
	pipe := s.client.Pipeline()
	pipe.Set(ctx, keyPrefixDevice+deviceCode, b, deviceTTL)
	normalized := normalizeUserCode(userCode)
	pipe.Set(ctx, keyPrefixUserCode+normalized, deviceCode, deviceTTL)
	pipe.Exec(ctx)
}

func (s *RedisStore) GetDeviceCode(deviceCode string) (*DeviceCode, bool) {
	ctx := context.Background()
	b, err := s.client.Get(ctx, keyPrefixDevice+deviceCode).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	var dc DeviceCode
	if json.Unmarshal(b, &dc) != nil {
		return nil, false
	}
	if dc.Expired || time.Now().After(dc.ExpiresAt) {
		s.client.Del(ctx, keyPrefixDevice+deviceCode)
		normalized := normalizeUserCode(dc.UserCode)
		s.client.Del(ctx, keyPrefixUserCode+normalized)
		return nil, false
	}
	return &dc, true
}

func (s *RedisStore) AuthorizeDeviceCode(userCode, userID string) bool {
	ctx := context.Background()
	normalized := normalizeUserCode(userCode)
	deviceCode, err := s.client.Get(ctx, keyPrefixUserCode+normalized).Result()
	if err == redis.Nil {
		return false
	}
	if err != nil {
		return false
	}
	b, err := s.client.Get(ctx, keyPrefixDevice+deviceCode).Bytes()
	if err == redis.Nil {
		return false
	}
	if err != nil {
		return false
	}
	var dc DeviceCode
	if json.Unmarshal(b, &dc) != nil {
		return false
	}
	if dc.Expired || time.Now().After(dc.ExpiresAt) {
		return false
	}
	dc.UserAuthorized = true
	dc.UserID = userID
	b2, _ := json.Marshal(&dc)
	s.client.Set(ctx, keyPrefixDevice+deviceCode, b2, deviceTTL)
	return true
}

func (s *RedisStore) DenyDeviceCode(userCode string) bool {
	ctx := context.Background()
	normalized := normalizeUserCode(userCode)
	deviceCode, err := s.client.Get(ctx, keyPrefixUserCode+normalized).Result()
	if err == redis.Nil {
		return false
	}
	if err != nil {
		return false
	}
	b, err := s.client.Get(ctx, keyPrefixDevice+deviceCode).Bytes()
	if err == redis.Nil {
		return false
	}
	if err != nil {
		return false
	}
	var dc DeviceCode
	if json.Unmarshal(b, &dc) != nil {
		return false
	}
	dc.AccessDenied = true
	b2, _ := json.Marshal(&dc)
	s.client.Set(ctx, keyPrefixDevice+deviceCode, b2, deviceTTL)
	return true
}

func (s *RedisStore) ConsumeDeviceCode(deviceCode string) (*DeviceCode, bool) {
	ctx := context.Background()
	key := keyPrefixDevice + deviceCode
	b, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	var dc DeviceCode
	if json.Unmarshal(b, &dc) != nil {
		return nil, false
	}
	if !dc.UserAuthorized || dc.Expired || time.Now().After(dc.ExpiresAt) {
		return nil, false
	}
	s.client.Del(ctx, key)
	normalized := normalizeUserCode(dc.UserCode)
	s.client.Del(ctx, keyPrefixUserCode+normalized)
	return &dc, true
}

func normalizeUserCode(userCode string) string {
	return strings.ToUpper(strings.ReplaceAll(userCode, "-", ""))
}

func (s *RedisStore) SaveMFAPending(challengeID string, pending *MFAPending) {
	pending.ExpiresAt = time.Now().Add(mfaTTL)
	b, _ := json.Marshal(pending)
	ctx := context.Background()
	s.client.Set(ctx, keyPrefixMFAPending+challengeID, b, mfaTTL)
}

func (s *RedisStore) GetMFAPending(challengeID string) (*MFAPending, bool) {
	ctx := context.Background()
	b, err := s.client.Get(ctx, keyPrefixMFAPending+challengeID).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	var p MFAPending
	if json.Unmarshal(b, &p) != nil {
		return nil, false
	}
	if time.Now().After(p.ExpiresAt) {
		s.client.Del(ctx, keyPrefixMFAPending+challengeID)
		return nil, false
	}
	return &p, true
}

func (s *RedisStore) ConsumeMFAPending(challengeID string) (*MFAPending, bool) {
	ctx := context.Background()
	key := keyPrefixMFAPending + challengeID
	b, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	var p MFAPending
	if json.Unmarshal(b, &p) != nil {
		return nil, false
	}
	if time.Now().After(p.ExpiresAt) {
		s.client.Del(ctx, key)
		return nil, false
	}
	s.client.Del(ctx, key)
	return &p, true
}

func (s *RedisStore) SaveSocialState(state string, data *SocialState) {
	data.ExpiresAt = time.Now().Add(socialStateTTL)
	b, _ := json.Marshal(data)
	ctx := context.Background()
	s.client.Set(ctx, keyPrefixSocialState+state, b, socialStateTTL)
}

func (s *RedisStore) GetSocialState(state string) (*SocialState, bool) {
	ctx := context.Background()
	b, err := s.client.Get(ctx, keyPrefixSocialState+state).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	var ss SocialState
	if json.Unmarshal(b, &ss) != nil {
		return nil, false
	}
	if time.Now().After(ss.ExpiresAt) {
		s.client.Del(ctx, keyPrefixSocialState+state)
		return nil, false
	}
	return &ss, true
}

func (s *RedisStore) ConsumeSocialState(state string) (*SocialState, bool) {
	ctx := context.Background()
	key := keyPrefixSocialState + state
	b, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	var ss SocialState
	if json.Unmarshal(b, &ss) != nil {
		return nil, false
	}
	if time.Now().After(ss.ExpiresAt) {
		s.client.Del(ctx, key)
		return nil, false
	}
	s.client.Del(ctx, key)
	return &ss, true
}

func (s *RedisStore) SaveWebAuthnSession(sessionID string, data []byte) {
	ctx := context.Background()
	s.client.Set(ctx, keyPrefixWebAuthnSess+sessionID, data, webauthnSessionTTL)
}

func (s *RedisStore) GetWebAuthnSession(sessionID string) ([]byte, bool) {
	ctx := context.Background()
	b, err := s.client.Get(ctx, keyPrefixWebAuthnSess+sessionID).Bytes()
	if err == redis.Nil || err != nil {
		return nil, false
	}
	return b, true
}

func (s *RedisStore) ConsumeWebAuthnSession(sessionID string) ([]byte, bool) {
	ctx := context.Background()
	key := keyPrefixWebAuthnSess + sessionID
	b, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil || err != nil {
		return nil, false
	}
	s.client.Del(ctx, key)
	return b, true
}
