package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	// DefaultBackupCodeCount is the number of backup codes to generate.
	DefaultBackupCodeCount = 10
	// BackupCodeLength is the character length of each code (e.g. XXXX-XXXX).
	BackupCodeLength = 8
	// BackupCodeChars for generating readable codes (exclude ambiguous: 0,O,1,I,L).
	BackupCodeChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// GenerateBackupCodes creates N one-time backup codes.
// Returns the raw codes (to show user once) and their SHA-256 hashes for storage.
func GenerateBackupCodes(n int) (codes []string, hashes []string, err error) {
	if n <= 0 {
		n = DefaultBackupCodeCount
	}
	codes = make([]string, n)
	hashes = make([]string, n)
	b := make([]byte, BackupCodeLength)
	for i := 0; i < n; i++ {
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		for j := range b {
			b[j] = BackupCodeChars[int(b[j])%len(BackupCodeChars)]
		}
		code := string(b[:4]) + "-" + string(b[4:])
		codes[i] = code
		hashes[i] = hashBackupCode(code)
	}
	return codes, hashes, nil
}

func hashBackupCode(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// VerifyBackupCode checks if the given code matches any of the stored hashes.
// Returns true and the index of the matching hash if valid, false otherwise.
// The caller must remove the consumed hash from storage.
func VerifyBackupCode(code string, storedHashes []string) (valid bool, consumedIndex int) {
	if len(storedHashes) == 0 {
		return false, -1
	}
	hash := hashBackupCode(code)
	for i, h := range storedHashes {
		if h != "" && h == hash {
			return true, i
		}
	}
	return false, -1
}
