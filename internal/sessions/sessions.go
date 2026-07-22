package sessions

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session holds authenticated user state.
type Session struct {
	SessionID string
	UserID    string
	Email     string
	ExpiresAt time.Time
}

// SessionCounter optionally exposes active session count for metrics.
type SessionCounter interface {
	Count() int
}

// Store manages server-side sessions.
// Implementations may be in-memory (single-instance) or Redis (multi-instance).
type Store interface {
	Create(userID, email string) (string, error)
	Get(sessionID string) (*Session, bool)
	Revoke(sessionID string)
}

// MemoryStore implements Store in-memory. Suitable for single-instance dev.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

// NewStore creates an in-memory session store. Default TTL is 24 hours.
func NewStore(ttl time.Duration) *MemoryStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &MemoryStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
}

// Create creates a new session for the user. Returns the session ID.
func (s *MemoryStore) Create(userID, email string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	sid := "sid_" + hex.EncodeToString(b)
	sess := &Session{
		SessionID: sid,
		UserID:    userID,
		Email:     email,
		ExpiresAt: time.Now().Add(s.ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanExpiredLocked()
	s.sessions[sid] = sess
	return sid, nil
}

// Get returns the session if valid. Extends TTL on access.
func (s *MemoryStore) Get(sessionID string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanExpiredLocked()
	sess, ok := s.sessions[sessionID]
	if !ok || sess == nil || time.Now().After(sess.ExpiresAt) {
		if ok {
			delete(s.sessions, sessionID)
		}
		return nil, false
	}
	sess.ExpiresAt = time.Now().Add(s.ttl)
	return sess, true
}

// Revoke removes a session (e.g. on logout).
func (s *MemoryStore) Revoke(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// Count returns the number of active (non-expired) sessions.
func (s *MemoryStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanExpiredLocked()
	return len(s.sessions)
}

func (s *MemoryStore) cleanExpiredLocked() {
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
}
