package mfa

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// IssuerLabel is the issuer name shown in authenticator apps.
	IssuerLabel = "auth2"
	// DefaultPeriod is the TOTP period in seconds (30s is standard).
	DefaultPeriod = 30
)

// GenerateSecret creates a new TOTP secret for the given account name (typically email).
// Returns the raw secret, the otp.Key for QR URI, and any error.
func GenerateSecret(accountName string) (secret string, key *otp.Key, err error) {
	key, err = totp.Generate(totp.GenerateOpts{
		Issuer:      IssuerLabel,
		AccountName: accountName,
		Period:      DefaultPeriod,
	})
	if err != nil {
		return "", nil, err
	}
	return key.Secret(), key, nil
}

// ValidateCode verifies the given TOTP code against the secret.
func ValidateCode(secret, code string) bool {
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    DefaultPeriod,
		Skew:      1, // allow 1 period (30s) before/after for clock skew
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}
