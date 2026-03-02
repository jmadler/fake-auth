package sessions

import (
	"testing"
	"time"
)

func TestCreateAndGet(t *testing.T) {
	store := NewStore(24 * time.Hour)
	sid, err := store.Create("user|1", "u@example.com")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sid == "" {
		t.Fatal("expected non-empty session ID")
	}

	sess, ok := store.Get(sid)
	if !ok {
		t.Fatal("Get should return session")
	}
	if sess == nil {
		t.Fatal("Get should return non-nil session")
	}
	if sess.UserID != "user|1" {
		t.Errorf("UserID = %q, want user|1", sess.UserID)
	}
	if sess.Email != "u@example.com" {
		t.Errorf("Email = %q, want u@example.com", sess.Email)
	}
}

func TestGet_expired(t *testing.T) {
	store := NewStore(1 * time.Millisecond)
	sid, err := store.Create("user|1", "u@example.com")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	sess, ok := store.Get(sid)
	if ok || sess != nil {
		t.Fatalf("Get should return nil for expired session, got ok=%v sess=%v", ok, sess)
	}
}

func TestRevoke(t *testing.T) {
	store := NewStore(24 * time.Hour)
	sid, err := store.Create("user|1", "u@example.com")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	store.Revoke(sid)

	sess, ok := store.Get(sid)
	if ok || sess != nil {
		t.Fatalf("Get should return nil after Revoke, got ok=%v sess=%v", ok, sess)
	}
}
