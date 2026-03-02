package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// VerifyS256 checks that the code_verifier hashes to the given code_challenge (base64url).
func VerifyS256(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	hash := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return computed == challenge
}

// VerifyPlain checks that verifier equals challenge (plain method).
func VerifyPlain(verifier, challenge string) bool {
	return verifier != "" && verifier == challenge
}

// Verify validates code_verifier against code_challenge. method is "S256" or "plain", default S256.
func Verify(verifier, challenge, method string) error {
	if verifier == "" {
		return errors.New("missing code_verifier")
	}
	if challenge == "" {
		return errors.New("missing code_challenge")
	}
	if method == "" {
		method = "S256"
	}
	switch method {
	case "S256":
		if !VerifyS256(verifier, challenge) {
			return errors.New("invalid code_verifier for S256 challenge")
		}
		return nil
	case "plain":
		if !VerifyPlain(verifier, challenge) {
			return errors.New("invalid code_verifier for plain challenge")
		}
		return nil
	default:
		return errors.New("unsupported code_challenge_method")
	}
}
