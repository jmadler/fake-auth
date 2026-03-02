package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyS256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	if !VerifyS256(verifier, challenge) {
		t.Error("VerifyS256 should succeed for matching verifier and challenge")
	}
	if VerifyS256("wrong", challenge) {
		t.Error("VerifyS256 should fail for wrong verifier")
	}
	if VerifyS256(verifier, "wrong") {
		t.Error("VerifyS256 should fail for wrong challenge")
	}
}

func TestVerifyPlain(t *testing.T) {
	if !VerifyPlain("same", "same") {
		t.Error("VerifyPlain should succeed when equal")
	}
	if VerifyPlain("a", "b") {
		t.Error("VerifyPlain should fail when different")
	}
}

func TestVerify(t *testing.T) {
	verifier := "test-verifier"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	if err := Verify(verifier, challenge, "S256"); err != nil {
		t.Errorf("Verify S256: %v", err)
	}
	if err := Verify(verifier, verifier, "plain"); err != nil {
		t.Errorf("Verify plain: %v", err)
	}
	if err := Verify("", challenge, "S256"); err == nil {
		t.Error("Verify should fail for empty verifier")
	}
	if err := Verify(verifier, "", "S256"); err == nil {
		t.Error("Verify should fail for empty challenge")
	}
	if err := Verify("wrong", challenge, "S256"); err == nil {
		t.Error("Verify should fail for invalid verifier")
	}
	if err := Verify(verifier, challenge, "invalid"); err == nil {
		t.Error("Verify should fail for unknown method")
	}
}
