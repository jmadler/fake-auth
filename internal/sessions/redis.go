package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	sessionKeyPrefix = "session:"
	defaultSessionTTL = 24 * time.Hour
)

// RedisStore implements Store using Redis.
type RedisStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewRedisStore creates a Redis-backed session store.
func NewRedisStore(redisURL string, ttl time.Duration) (*RedisStore, error) {
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
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	return &RedisStore{client: client, ttl: ttl}, nil
}

// Client returns the Redis client for health checks and graceful shutdown.
func (s *RedisStore) Client() *redis.Client { return s.client }

// Close closes the Redis connection.
func (s *RedisStore) Close() error { return s.client.Close() }

// Create creates a new session for the user. Returns the session ID.
func (s *RedisStore) Create(userID, email string) (string, error) {
	rb := make([]byte, 16)
	if _, err := rand.Read(rb); err != nil {
		return "", err
	}
	sid := "sid_" + hex.EncodeToString(rb)
	sess := &Session{
		SessionID: sid,
		UserID:    userID,
		Email:     email,
		ExpiresAt: time.Now().Add(s.ttl),
	}
	b, _ := json.Marshal(sess)
	ctx := context.Background()
	s.client.Set(ctx, sessionKeyPrefix+sid, b, s.ttl)
	return sid, nil
}

// Get returns the session if valid. Extends TTL on access.
func (s *RedisStore) Get(sessionID string) (*Session, bool) {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID
	b, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	var sess Session
	if json.Unmarshal(b, &sess) != nil {
		s.client.Del(ctx, key)
		return nil, false
	}
	if time.Now().After(sess.ExpiresAt) {
		s.client.Del(ctx, key)
		return nil, false
	}
	// Extend TTL on access
	sess.ExpiresAt = time.Now().Add(s.ttl)
	b2, _ := json.Marshal(&sess)
	s.client.Set(ctx, key, b2, s.ttl)
	return &sess, true
}

// Revoke removes a session (e.g. on logout).
func (s *RedisStore) Revoke(sessionID string) {
	ctx := context.Background()
	s.client.Del(ctx, sessionKeyPrefix+sessionID)
}

// Count returns the number of active sessions (keys with session: prefix).
func (s *RedisStore) Count() int {
	ctx := context.Background()
	keys, err := s.client.Keys(ctx, sessionKeyPrefix+"*").Result()
	if err != nil {
		return 0
	}
	return len(keys)
}
