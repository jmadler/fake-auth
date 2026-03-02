package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const defaultKid = "default"

type Issuer struct {
	issuer string
	key    *rsa.PrivateKey
	kid    string
}

func NewIssuer(issuer string) (*Issuer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kid := defaultKid
	if id, err := uuid.NewRandom(); err == nil {
		kid = id.String()[:8]
	}
	return &Issuer{issuer: issuer, key: key, kid: kid}, nil
}

func NewIssuerWithKey(issuer string, key *rsa.PrivateKey) *Issuer {
	kid := defaultKid
	if id, err := uuid.NewRandom(); err == nil {
		kid = id.String()[:8]
	}
	return &Issuer{issuer: issuer, key: key, kid: kid}
}

func (i *Issuer) SetKid(kid string) {
	i.kid = kid
}

// IDTokenOptions holds optional claims for OIDC id_token.
type IDTokenOptions struct {
	Nonce        string            // nonce claim for replay protection
	AMR          []string          // authentication method references, e.g. ["password"]
	AccessToken  string            // for at_hash
	AuthCode     string            // for c_hash (hybrid flow)
	SessionID    string            // sid claim
	CustomClaims map[string]interface{} // extra claims from rules
}

func (i *Issuer) Issue(sub, aud, clientID string, expiresIn int, customClaims map[string]interface{}) (string, error) {
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": sub,
		"iss": i.issuer,
		"aud": aud,
		"exp": now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"iat": now.Unix(),
	}
	if clientID != "" {
		claims["azp"] = clientID
	}
	for k, v := range customClaims {
		claims[k] = v
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = i.kid
	return t.SignedString(i.key)
}

// leftHalfHash returns base64url(left 16 bytes of SHA256) for at_hash/c_hash.
func leftHalfHash(input string) string {
	h := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(h[:16])
}

// IssueIDToken issues an OIDC ID token with user claims. Scope can include "openid", "profile", "email"
// to control which claims are included (for mock we include all when requested).
func (i *Issuer) IssueIDToken(sub, aud, clientID string, expiresIn int, scope, email, name, picture string, opts *IDTokenOptions) (string, error) {
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":        sub,
		"iss":        i.issuer,
		"aud":        aud,
		"exp":        now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"iat":        now.Unix(),
		"auth_time":  now.Unix(),
	}
	if clientID != "" {
		claims["azp"] = clientID
	}
	if opts != nil {
		if opts.Nonce != "" {
			claims["nonce"] = opts.Nonce
		}
		if len(opts.AMR) > 0 {
			claims["amr"] = opts.AMR
		}
		if opts.AccessToken != "" {
			claims["at_hash"] = leftHalfHash(opts.AccessToken)
		}
		if opts.AuthCode != "" {
			claims["c_hash"] = leftHalfHash(opts.AuthCode)
		}
		if opts.SessionID != "" {
			claims["sid"] = opts.SessionID
		}
		for k, v := range opts.CustomClaims {
			claims[k] = v
		}
	}
	if scope == "" {
		scope = "openid profile email"
	}
	if strings.Contains(scope, "email") && email != "" {
		claims["email"] = email
		claims["email_verified"] = true
	}
	if (strings.Contains(scope, "profile") || strings.Contains(scope, "openid")) && name != "" {
		claims["name"] = name
		parts := strings.SplitN(name, " ", 2)
		if len(parts) > 0 {
			claims["given_name"] = parts[0]
		}
		if len(parts) > 1 {
			claims["family_name"] = parts[1]
		}
		claims["nickname"] = name
		if picture != "" {
			claims["picture"] = picture
		}
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = i.kid
	return t.SignedString(i.key)
}

// Validate parses and verifies a JWT, returning the claims.
func (i *Issuer) Validate(tokenStr string) (jwt.MapClaims, error) {
	tok, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) {
		return i.key.Public(), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	// Validate issuer (accept with or without trailing slash)
	iss, _ := claims["iss"].(string)
	expected := strings.TrimSuffix(i.issuer, "/")
	expectedWithSlash := expected + "/"
	if iss != expected && iss != expectedWithSlash {
		return nil, errors.New("invalid issuer")
	}
	return claims, nil
}

func (i *Issuer) JWKS() ([]byte, error) {
	pub := i.key.Public().(*rsa.PublicKey)
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eb := big.NewInt(int64(pub.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eb)
	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": i.kid,
		"n":   n,
		"e":   e,
	}
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	return json.Marshal(jwks)
}
