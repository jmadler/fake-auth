package mfa

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func generateCodeForTest(secret string) (string, error) {
	return totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period: DefaultPeriod,
		Digits: 6,
	})
}

func TestGenerateSecret(t *testing.T) {
	secret, key, err := GenerateSecret("test@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if secret == "" {
		t.Error("secret should not be empty")
	}
	if key == nil {
		t.Error("key should not be nil")
	}
	uri := key.URL()
	if uri == "" || len(uri) < 20 {
		t.Errorf("URL should be a valid otpauth URI, got %q", uri)
	}
	if key.Secret() != secret {
		t.Error("key.Secret() should match returned secret")
	}
}

func TestValidateCode(t *testing.T) {
	secret, _, err := GenerateSecret("test@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	// ValidateCode with wrong code should fail
	if ValidateCode(secret, "000000") {
		t.Error("wrong code should not validate")
	}
	if ValidateCode(secret, "") {
		t.Error("empty code should not validate")
	}
	// Valid code - use totp to generate current code
	code, err := generateCodeForTest(secret)
	if err != nil {
		t.Skipf("cannot generate test code: %v", err)
	}
	if !ValidateCode(secret, code) {
		t.Errorf("valid code %q should validate", code)
	}
}
