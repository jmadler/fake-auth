package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Issuer struct {
	issuer string
	key    *rsa.PrivateKey
}

func NewIssuer(issuer string) (*Issuer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Issuer{issuer: issuer, key: key}, nil
}

func (i *Issuer) Issue(sub, aud, clientID string, expiresIn int) (string, error) {
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
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(i.key)
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
		"n":   n,
		"e":   e,
	}
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	return json.Marshal(jwks)
}
