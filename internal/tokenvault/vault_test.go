package tokenvault

import (
	"encoding/hex"
	"os"
	"testing"
)

func TestEncryptDecrypt_NoKey(t *testing.T) {
	os.Unsetenv("TOKEN_VAULT_KEY")
	_, err := Encrypt("secret")
	if err == nil {
		t.Error("Encrypt without key should fail")
	}
	_, err = Decrypt("x")
	if err == nil {
		t.Error("Decrypt without key should fail")
	}
}

func TestEncryptDecrypt_ShortKey(t *testing.T) {
	os.Setenv("TOKEN_VAULT_KEY", "short")
	defer os.Unsetenv("TOKEN_VAULT_KEY")
	_, err := Encrypt("secret")
	if err == nil {
		t.Error("Encrypt with short key should fail")
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte('a' + (i % 26))
	}
	os.Setenv("TOKEN_VAULT_KEY", string(key))
	defer os.Unsetenv("TOKEN_VAULT_KEY")

	plain := "my-access-token-12345"
	ct, err := Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ct == "" || ct == plain {
		t.Error("Ciphertext should not be empty or equal to plaintext")
	}
	dec, err := Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if dec != plain {
		t.Errorf("Decrypt roundtrip: got %q, want %q", dec, plain)
	}
}

func TestEncryptDecrypt_HexKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte('A' + (i % 26))
	}
	os.Setenv("TOKEN_VAULT_KEY", "hex:"+hex.EncodeToString(key))
	defer os.Unsetenv("TOKEN_VAULT_KEY")

	plain := "token"
	ct, err := Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt with hex key: %v", err)
	}
	dec, err := Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if dec != plain {
		t.Errorf("roundtrip: got %q", dec)
	}
}

func TestEncryptDecrypt_InvalidHexKey(t *testing.T) {
	os.Setenv("TOKEN_VAULT_KEY", "hex:notvalidhex")
	defer os.Unsetenv("TOKEN_VAULT_KEY")
	_, err := Encrypt("x")
	if err == nil {
		t.Error("Invalid hex key should fail")
	}
}

func TestEnabled(t *testing.T) {
	os.Unsetenv("TOKEN_VAULT_ENABLED")
	if Enabled() {
		t.Error("Expected disabled when unset")
	}
	os.Setenv("TOKEN_VAULT_ENABLED", "true")
	if !Enabled() {
		t.Error("Expected enabled")
	}
	os.Setenv("TOKEN_VAULT_ENABLED", "TRUE")
	if !Enabled() {
		t.Error("Case insensitive")
	}
	os.Unsetenv("TOKEN_VAULT_ENABLED")
}
