package tokenvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Encrypt encrypts plaintext with AES-GCM using key from TOKEN_VAULT_KEY env.
func Encrypt(plaintext string) (string, error) {
	key := os.Getenv("TOKEN_VAULT_KEY")
	if key == "" {
		return "", fmt.Errorf("TOKEN_VAULT_KEY must be set")
	}
	var keyBytes []byte
	if strings.HasPrefix(key, "hex:") {
		var err error
		keyBytes, err = hex.DecodeString(strings.TrimPrefix(key, "hex:"))
		if err != nil {
			return "", fmt.Errorf("invalid TOKEN_VAULT_KEY hex: %w", err)
		}
	} else {
		keyBytes = []byte(key)
	}
	if len(keyBytes) < 32 {
		return "", fmt.Errorf("TOKEN_VAULT_KEY must be at least 32 bytes")
	}
	block, err := aes.NewCipher(keyBytes[:32])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext encrypted with Encrypt.
func Decrypt(ciphertextB64 string) (string, error) {
	key := os.Getenv("TOKEN_VAULT_KEY")
	if key == "" {
		return "", fmt.Errorf("TOKEN_VAULT_KEY must be set")
	}
	var keyBytes []byte
	if strings.HasPrefix(key, "hex:") {
		var err error
		keyBytes, err = hex.DecodeString(strings.TrimPrefix(key, "hex:"))
		if err != nil {
			return "", fmt.Errorf("invalid TOKEN_VAULT_KEY hex: %w", err)
		}
	} else {
		keyBytes = []byte(key)
	}
	if len(keyBytes) < 32 {
		return "", fmt.Errorf("TOKEN_VAULT_KEY must be at least 32 bytes")
	}
	block, err := aes.NewCipher(keyBytes[:32])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// Enabled returns true when Token Vault is enabled.
func Enabled() bool {
	return strings.ToLower(os.Getenv("TOKEN_VAULT_ENABLED")) == "true"
}

// StoreRequest is the JSON body for POST /api/v2/token-vault.
type StoreRequest struct {
	Name        string                 `json:"name"`
	AccessToken string                 `json:"access_token"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Validate checks StoreRequest. Returns error description or "".
func (r *StoreRequest) Validate() string {
	if r.Name == "" {
		return "name is required"
	}
	if r.AccessToken == "" {
		return "access_token is required"
	}
	return ""
}

// MetadataJSON returns Metadata as JSON string.
func (r *StoreRequest) MetadataJSON() string {
	if r.Metadata == nil {
		return "{}"
	}
	b, _ := json.Marshal(r.Metadata)
	return string(b)
}
