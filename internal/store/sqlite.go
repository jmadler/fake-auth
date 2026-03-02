package store

import (
	"context"
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLite(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			display_name TEXT,
			organization_id INTEGER DEFAULT 1,
			enterprise_id INTEGER DEFAULT 1,
			role TEXT DEFAULT 'user',
			app_metadata TEXT,
			user_metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	`)
	return err
}

func (s *SQLiteStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	var id, em, hash, displayName string
	var orgID, entID int
	var role, appMeta sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, organization_id, enterprise_id, role, app_metadata FROM users WHERE email = ?`,
		email,
	).Scan(&id, &em, &hash, &displayName, &orgID, &entID, &role, &appMeta)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u := &User{ID: id, Email: em, PasswordHash: hash, DisplayName: displayName, OrganizationID: orgID, EnterpriseID: entID}
	if role.Valid {
		u.Role = role.String
	}
	return u, nil
}

func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*User, error) {
	var uid, em, hash, displayName string
	var orgID, entID int
	var role, appMeta sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, organization_id, enterprise_id, role, app_metadata FROM users WHERE id = ?`,
		id,
	).Scan(&uid, &em, &hash, &displayName, &orgID, &entID, &role, &appMeta)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u := &User{ID: uid, Email: em, PasswordHash: hash, DisplayName: displayName, OrganizationID: orgID, EnterpriseID: entID}
	if role.Valid {
		u.Role = role.String
	}
	return u, nil
}

func (s *SQLiteStore) Create(ctx context.Context, u *User) error {
	return s.CreateUser(ctx, u, u.PasswordHash)
}

func (s *SQLiteStore) UpdateAppMetadata(ctx context.Context, id string, meta map[string]interface{}) error {
	// Stub: SQLite store doesn't persist app_metadata for Management API; no-op for local mock
	return nil
}

func (s *SQLiteStore) VerifyPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// Ensure User.VerifyPassword works when store has the hash
func (u *User) VerifyPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

func (s *SQLiteStore) CreateUser(ctx context.Context, u *User, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, display_name, organization_id, enterprise_id, role) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.PasswordHash, u.DisplayName, u.OrganizationID, u.EnterpriseID, u.Role,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}
