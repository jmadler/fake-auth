package mfa

import (
	"testing"
)

func TestGenerateBackupCodes(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes(10)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}
	if len(codes) != 10 || len(hashes) != 10 {
		t.Errorf("want 10 codes and hashes, got %d, %d", len(codes), len(hashes))
	}
	seen := make(map[string]bool)
	for i, c := range codes {
		if len(c) != 9 { // XXXX-XXXX
			t.Errorf("code %d has wrong format: %q", i, c)
		}
		if seen[c] {
			t.Errorf("duplicate code: %q", c)
		}
		seen[c] = true
		if hashes[i] == "" {
			t.Errorf("hash %d should not be empty", i)
		}
	}
}

func TestVerifyBackupCode(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes(5)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}
	valid, idx := VerifyBackupCode(codes[0], hashes)
	if !valid || idx != 0 {
		t.Errorf("VerifyBackupCode(codes[0]): want valid=true, idx=0, got valid=%v, idx=%d", valid, idx)
	}
	valid, _ = VerifyBackupCode("invalid", hashes)
	if valid {
		t.Error("invalid code should not verify")
	}
	valid, _ = VerifyBackupCode(codes[0], []string{})
	if valid {
		t.Error("empty hashes should not verify")
	}
}
