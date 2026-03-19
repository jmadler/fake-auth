package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSeedFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "auth0.db")
	st, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer st.Close()

	cfgPath := filepath.Join(dir, "users.json")
	cfg := map[string]interface{}{
		"users": []map[string]interface{}{
			{"id": "auth0|seed-1", "email": "seed1@test.local", "password": "pass1", "display_name": "Seed 1", "role": "vet"},
			{"id": "auth0|seed-2", "email": "seed2@test.local", "password": "pass2", "display_name": "Seed 2", "role": "admin"},
		},
	}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, b, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx := context.Background()
	if err := st.SeedFromConfigFile(ctx, cfgPath); err != nil {
		t.Fatalf("SeedFromConfigFile: %v", err)
	}

	u1, err := st.GetByEmail(ctx, "seed1@test.local")
	if err != nil || u1 == nil {
		t.Fatalf("GetByEmail seed1: %v", err)
	}
	if u1.ID != "auth0|seed-1" || u1.DisplayName != "Seed 1" || u1.Role != "vet" {
		t.Errorf("seed1: id=%s display=%s role=%s", u1.ID, u1.DisplayName, u1.Role)
	}
	if !st.VerifyPassword(u1.PasswordHash, "pass1") {
		t.Error("seed1 password verify failed")
	}

	u2, err := st.GetByEmail(ctx, "seed2@test.local")
	if err != nil || u2 == nil {
		t.Fatalf("GetByEmail seed2: %v", err)
	}
	if u2.ID != "auth0|seed-2" || u2.Role != "admin" {
		t.Errorf("seed2: id=%s role=%s", u2.ID, u2.Role)
	}
	if !st.VerifyPassword(u2.PasswordHash, "pass2") {
		t.Error("seed2 password verify failed")
	}

	// Idempotent: run again, should not error
	if err := st.SeedFromConfigFile(ctx, cfgPath); err != nil {
		t.Fatalf("SeedFromConfigFile (idempotent): %v", err)
	}
}

func TestSeedFromConfigFileMissingFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "auth0.db")
	st, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer st.Close()

	err = st.SeedFromConfigFile(context.Background(), filepath.Join(dir, "nonexistent.json"))
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestSeedFromConfigFileEmptyUsers(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "auth0.db")
	st, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer st.Close()

	cfgPath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(cfgPath, []byte(`{"users":[]}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := st.SeedFromConfigFile(context.Background(), cfgPath); err != nil {
		t.Fatalf("SeedFromConfigFile empty: %v", err)
	}
}
