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

// Store manages server-side sessions. In-memory with TTL; suitable for single-instance dev.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

// NewStore creates a session store. Default TTL is 24 hours.
func NewStore(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Store{
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
}

// Create creates a new session for the user. Returns the session ID.
func (s *Store) Create(userID, email string) (string, error) {
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

// Get returns the session if valid. Consumes (extends) the session.
func (s *Store) Get(sessionID string) (*Session, bool) {
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
	// Extend TTL on access
	sess.ExpiresAt = time.Now().Add(s.ttl)
	return sess, true
}

// Revoke removes a session (e.g. on logout).
func (s *Store) Revoke(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

func (s *Store) cleanExpiredLocked() {
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
}
