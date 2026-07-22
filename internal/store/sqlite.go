package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmadler/auth2/internal/mfa"
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
			email_verified INTEGER DEFAULT 0,
			organization_id INTEGER DEFAULT 1,
			enterprise_id INTEGER DEFAULT 1,
			role TEXT DEFAULT 'user',
			app_metadata TEXT,
			user_metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
		CREATE TABLE IF NOT EXISTS roles (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			description TEXT
		);
		CREATE TABLE IF NOT EXISTS permissions (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			resource_server_identifier TEXT,
			description TEXT
		);
		CREATE TABLE IF NOT EXISTS user_roles (
			user_id TEXT NOT NULL,
			role_id TEXT NOT NULL,
			PRIMARY KEY (user_id, role_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (role_id) REFERENCES roles(id)
		);
		CREATE TABLE IF NOT EXISTS role_permissions (
			role_id TEXT NOT NULL,
			permission_id TEXT NOT NULL,
			PRIMARY KEY (role_id, permission_id),
			FOREIGN KEY (role_id) REFERENCES roles(id),
			FOREIGN KEY (permission_id) REFERENCES permissions(id)
		);
		CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			name TEXT,
			app_type TEXT,
			callbacks TEXT,
			allowed_origins TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS connections (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			strategy TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS user_blocks (
			user_id TEXT PRIMARY KEY,
			blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT,
			user_id TEXT,
			client_id TEXT,
			payload TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
		CREATE TABLE IF NOT EXISTS password_reset_tokens (
			token TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS login_attempts (
			identifier TEXT PRIMARY KEY,
			attempt_count INTEGER DEFAULT 0,
			locked_until DATETIME,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS mfa_enrollment (
			user_id TEXT PRIMARY KEY,
			totp_secret TEXT NOT NULL,
			backup_codes_hash TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS user_identities (
			user_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			provider_user_id TEXT NOT NULL,
			PRIMARY KEY (provider, provider_user_id),
			UNIQUE (user_id, provider),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE INDEX IF NOT EXISTS idx_user_identities_user_id ON user_identities(user_id);
		CREATE TABLE IF NOT EXISTS passwordless_tokens (
			token TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			state TEXT,
			response_type TEXT DEFAULT 'code',
			scope TEXT DEFAULT 'openid',
			audience TEXT,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_passwordless_tokens_expires ON passwordless_tokens(expires_at);
		CREATE TABLE IF NOT EXISTS user_known_ips (
			user_id TEXT NOT NULL,
			ip TEXT NOT NULL,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, ip),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE INDEX IF NOT EXISTS idx_user_known_ips_user_id ON user_known_ips(user_id);
		CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id BLOB NOT NULL,
			public_key BLOB NOT NULL,
			attestation_type TEXT DEFAULT '',
			transports TEXT DEFAULT '[]',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_cred_id ON webauthn_credentials(credential_id);
		CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
		CREATE TABLE IF NOT EXISTS organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			display_name TEXT,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS org_members (
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'member',
			PRIMARY KEY (org_id, user_id),
			FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_org_members_user_id ON org_members(user_id);
		CREATE TABLE IF NOT EXISTS org_connections (
			org_id TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			PRIMARY KEY (org_id, connection_id),
			FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
			FOREIGN KEY (connection_id) REFERENCES connections(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS enterprise_connections (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			name TEXT NOT NULL,
			domain_hint TEXT,
			issuer_url TEXT NOT NULL,
			client_id TEXT NOT NULL,
			client_secret TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_enterprise_connections_org_id ON enterprise_connections(org_id);
		CREATE INDEX IF NOT EXISTS idx_enterprise_connections_domain ON enterprise_connections(domain_hint);
		CREATE TABLE IF NOT EXISTS invitations (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			email TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'member',
			token TEXT UNIQUE NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_invitations_token ON invitations(token);
		CREATE INDEX IF NOT EXISTS idx_invitations_org_id ON invitations(org_id);
		CREATE TABLE IF NOT EXISTS saml_service_providers (
			id TEXT PRIMARY KEY,
			entity_id TEXT NOT NULL UNIQUE,
			acs_url TEXT NOT NULL,
			certificate TEXT,
			metadata_url TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_saml_sp_entity_id ON saml_service_providers(entity_id);
		CREATE TABLE IF NOT EXISTS oidc_enterprise_connections (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			issuer_url TEXT NOT NULL,
			client_id TEXT NOT NULL,
			client_secret TEXT NOT NULL,
			scope TEXT DEFAULT 'openid email profile',
			domain_hint TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_oidc_enterprise_conn_name ON oidc_enterprise_connections(name);
		CREATE TABLE IF NOT EXISTS ciba_requests (
			auth_req_id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			login_hint TEXT NOT NULL,
			scope TEXT DEFAULT 'openid',
			audience TEXT,
			status TEXT NOT NULL DEFAULT 'pending',
			user_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_ciba_requests_status ON ciba_requests(status);
		CREATE INDEX IF NOT EXISTS idx_ciba_requests_expires ON ciba_requests(expires_at);
		CREATE TABLE IF NOT EXISTS token_vault (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			user_id TEXT NOT NULL,
			access_token_encrypted TEXT NOT NULL,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(name, user_id)
		);
		CREATE INDEX IF NOT EXISTS idx_token_vault_name_user ON token_vault(name, user_id);
		CREATE INDEX IF NOT EXISTS idx_token_vault_user ON token_vault(user_id);
	`)
	if err != nil {
		return err
	}
	// Add columns if missing (for existing DBs)
	_, _ = s.db.Exec(`ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0`)
	_, _ = s.db.Exec(`ALTER TABLE users ADD COLUMN phone_number TEXT`)
	_, _ = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone_number)`)
	_, _ = s.db.Exec(`ALTER TABLE passwordless_tokens ADD COLUMN token_type TEXT DEFAULT 'magiclink'`)
	_, _ = s.db.Exec(`ALTER TABLE passwordless_tokens ADD COLUMN phone TEXT`)
	_, _ = s.db.Exec(`ALTER TABLE passwordless_tokens ADD COLUMN code TEXT`)
	_, _ = s.db.Exec(`CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		credential_id BLOB NOT NULL,
		public_key BLOB NOT NULL,
		attestation_type TEXT DEFAULT '',
		transports TEXT DEFAULT '[]',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	)`)
	_, _ = s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_cred_id ON webauthn_credentials(credential_id)`)
	_, _ = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id)`)
	if err := s.seedRoles(); err != nil {
		return err
	}
	return s.seedClientsAndConnections()
}

func (s *SQLiteStore) seedRoles() error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO roles (id, name, description) VALUES ('rol_default', 'user', 'Default user role');
		INSERT OR IGNORE INTO roles (id, name, description) VALUES ('rol_admin', 'admin', 'Administrator role');
		INSERT OR IGNORE INTO permissions (id, name, resource_server_identifier, description) VALUES ('perm_read', 'read:users', 'https://api.example.com', 'Read users');
		INSERT OR IGNORE INTO permissions (id, name, resource_server_identifier, description) VALUES ('perm_write', 'write:users', 'https://api.example.com', 'Write users');
		INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('rol_default', 'perm_read');
		INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('rol_admin', 'perm_read');
		INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES ('rol_admin', 'perm_write');
	`)
	return err
}

func (s *SQLiteStore) seedClientsAndConnections() error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO clients (id, name, app_type, callbacks, allowed_origins) VALUES ('e2e-test', 'E2E Test', 'spa', 'http://localhost:3000/callback,http://localhost/callback', 'http://localhost:3000,http://localhost');
		INSERT OR IGNORE INTO clients (id, name, app_type, callbacks, allowed_origins) VALUES ('default', 'auth0', 'regular_web', 'http://localhost/callback', '');
		INSERT OR IGNORE INTO connections (id, name, strategy) VALUES ('con_db_main', 'Username-Password-Authentication', 'auth0');
		INSERT OR IGNORE INTO connections (id, name, strategy) VALUES ('con_email', 'email', 'email');
		INSERT OR IGNORE INTO connections (id, name, strategy) VALUES ('con_google', 'google-oauth2', 'google-oauth2');
		INSERT OR IGNORE INTO connections (id, name, strategy) VALUES ('con_github', 'github', 'github');
	`)
	return err
}

func parseJSONMap(s sql.NullString) map[string]interface{} {
	if !s.Valid || s.String == "" {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s.String), &m); err != nil {
		return nil
	}
	return m
}

func (s *SQLiteStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	var id, em, hash, displayName string
	var orgID, entID int
	var emailVerified int
	var role, appMeta, userMeta, phoneNum sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, COALESCE(email_verified, 0), organization_id, enterprise_id, role, app_metadata, user_metadata, phone_number FROM users WHERE email = ?`,
		email,
	).Scan(&id, &em, &hash, &displayName, &emailVerified, &orgID, &entID, &role, &appMeta, &userMeta, &phoneNum)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u := &User{ID: id, Email: em, PasswordHash: hash, DisplayName: displayName, EmailVerified: emailVerified != 0, OrganizationID: orgID, EnterpriseID: entID}
	if phoneNum.Valid {
		u.PhoneNumber = phoneNum.String
	}
	if role.Valid {
		u.Role = role.String
	}
	u.AppMetadata = parseJSONMap(appMeta)
	u.UserMetadata = parseJSONMap(userMeta)
	return u, nil
}

func (s *SQLiteStore) GetByPhone(ctx context.Context, phone string) (*User, error) {
	if phone == "" {
		return nil, nil
	}
	var id, em, hash, displayName string
	var orgID, entID int
	var emailVerified int
	var role, appMeta, userMeta, phoneNum sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, COALESCE(email_verified, 0), organization_id, enterprise_id, role, app_metadata, user_metadata, phone_number FROM users WHERE phone_number = ?`,
		phone,
	).Scan(&id, &em, &hash, &displayName, &emailVerified, &orgID, &entID, &role, &appMeta, &userMeta, &phoneNum)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u := &User{ID: id, Email: em, PasswordHash: hash, DisplayName: displayName, EmailVerified: emailVerified != 0, OrganizationID: orgID, EnterpriseID: entID}
	if role.Valid {
		u.Role = role.String
	}
	if phoneNum.Valid {
		u.PhoneNumber = phoneNum.String
	}
	u.AppMetadata = parseJSONMap(appMeta)
	u.UserMetadata = parseJSONMap(userMeta)
	return u, nil
}

func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*User, error) {
	var uid, em, hash, displayName string
	var orgID, entID int
	var emailVerified int
	var role, appMeta, userMeta, phoneNum sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, COALESCE(email_verified, 0), organization_id, enterprise_id, role, app_metadata, user_metadata, phone_number FROM users WHERE id = ?`,
		id,
	).Scan(&uid, &em, &hash, &displayName, &emailVerified, &orgID, &entID, &role, &appMeta, &userMeta, &phoneNum)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u := &User{ID: uid, Email: em, PasswordHash: hash, DisplayName: displayName, EmailVerified: emailVerified != 0, OrganizationID: orgID, EnterpriseID: entID}
	if role.Valid {
		u.Role = role.String
	}
	if phoneNum.Valid {
		u.PhoneNumber = phoneNum.String
	}
	u.AppMetadata = parseJSONMap(appMeta)
	u.UserMetadata = parseJSONMap(userMeta)
	return u, nil
}

func (s *SQLiteStore) Create(ctx context.Context, u *User) error {
	return s.CreateUser(ctx, u, u.PasswordHash)
}

func (s *SQLiteStore) UpdateAppMetadata(ctx context.Context, id string, meta map[string]interface{}) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET app_metadata = ? WHERE id = ?`, string(b), id)
	return err
}

func (s *SQLiteStore) VerifyPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Ping verifies the database connection is alive.
func (s *SQLiteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
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

func jsonBytes(m map[string]interface{}) string {
	if m == nil {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (s *SQLiteStore) CreateUser(ctx context.Context, u *User, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	emailVerified := 0
	if u.EmailVerified {
		emailVerified = 1
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, display_name, email_verified, organization_id, enterprise_id, role, app_metadata, user_metadata, phone_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.PasswordHash, u.DisplayName, emailVerified, u.OrganizationID, u.EnterpriseID, u.Role, jsonBytes(u.AppMetadata), jsonBytes(u.UserMetadata), u.PhoneNumber,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	roleID := "rol_default"
	if u.Role == "admin" {
		roleID = "rol_admin"
	}
	s.db.ExecContext(ctx, `INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)`, u.ID, roleID)
	return nil
}

func (s *SQLiteStore) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.name, r.description FROM roles r
		 JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.Name, &r.Description); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, nil
}

func (s *SQLiteStore) GetUserPermissions(ctx context.Context, userID string) ([]Permission, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT p.id, p.name, p.resource_server_identifier, p.description
		 FROM permissions p
		 JOIN role_permissions rp ON rp.permission_id = p.id
		 JOIN user_roles ur ON ur.role_id = rp.role_id
		 WHERE ur.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var perms []Permission
	for rows.Next() {
		var p Permission
		var rsIdent, desc sql.NullString
		if err := rows.Scan(&p.ID, &p.Name, &rsIdent, &desc); err != nil {
			return nil, err
		}
		if rsIdent.Valid {
			p.ResourceServerIdentifier = rsIdent.String
		}
		if desc.Valid {
			p.Description = desc.String
		}
		perms = append(perms, p)
	}
	return perms, nil
}

func (s *SQLiteStore) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description FROM roles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []Role
	for rows.Next() {
		var r Role
		var desc sql.NullString
		if err := rows.Scan(&r.ID, &r.Name, &desc); err != nil {
			return nil, err
		}
		if desc.Valid {
			r.Description = desc.String
		}
		roles = append(roles, r)
	}
	return roles, nil
}

func (s *SQLiteStore) AssignRoleToUser(ctx context.Context, userID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)`, userID, roleID)
	return err
}

func (s *SQLiteStore) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ? AND role_id = ?`, userID, roleID)
	return err
}

func (s *SQLiteStore) ListUsers(ctx context.Context, opts ListUsersOpts) ([]User, int, error) {
	if opts.PerPage <= 0 {
		opts.PerPage = 50
	}
	if opts.PerPage > 100 {
		opts.PerPage = 100
	}
	offset := opts.Page * opts.PerPage

	q := opts.Query
	q = strings.TrimSpace(strings.TrimPrefix(q, "email:"))
	q = strings.Trim(strings.TrimPrefix(q, "\""), "\"")

	var rows *sql.Rows
	var err error
	if q != "" {
		pattern := "%" + q + "%"
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, password_hash, display_name, organization_id, enterprise_id, role FROM users 
			 WHERE email LIKE ? OR display_name LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
			pattern, pattern, opts.PerPage, offset)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, password_hash, display_name, organization_id, enterprise_id, role FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
			opts.PerPage, offset)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var role sql.NullString
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.OrganizationID, &u.EnterpriseID, &role); err != nil {
			return nil, 0, err
		}
		if role.Valid {
			u.Role = role.String
		}
		users = append(users, u)
	}

	var total int
	if q != "" {
		pattern := "%" + q + "%"
		s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE email LIKE ? OR display_name LIKE ?`, pattern, pattern).Scan(&total)
	} else {
		s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&total)
	}
	return users, total, nil
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, id string, updates map[string]interface{}) error {
	var set []string
	var args []interface{}
	if v, ok := updates["email"].(string); ok {
		set = append(set, "email = ?")
		args = append(args, v)
	}
	if v, ok := updates["name"].(string); ok {
		set = append(set, "display_name = ?")
		args = append(args, v)
	}
	if v, ok := updates["display_name"].(string); ok {
		set = append(set, "display_name = ?")
		args = append(args, v)
	}
	if v, ok := updates["user_metadata"].(map[string]interface{}); ok {
		set = append(set, "user_metadata = ?")
		args = append(args, jsonBytes(v))
	}
	if v, ok := updates["app_metadata"].(map[string]interface{}); ok {
		set = append(set, "app_metadata = ?")
		args = append(args, jsonBytes(v))
	}
	if v, ok := updates["email_verified"].(bool); ok {
		ev := 0
		if v {
			ev = 1
		}
		set = append(set, "email_verified = ?")
		args = append(args, ev)
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.ExecContext(ctx, `UPDATE users SET `+strings.Join(set, ", ")+` WHERE id = ?`, args...)
	return err
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE user_id = ?`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM user_identities WHERE user_id = ?`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM mfa_enrollment WHERE user_id = ?`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ?`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM user_blocks WHERE user_id = ?`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	var r Role
	var desc sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, name, description FROM roles WHERE id = ?`, id).
		Scan(&r.ID, &r.Name, &desc)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if desc.Valid {
		r.Description = desc.String
	}
	return &r, nil
}

func (s *SQLiteStore) CreateRole(ctx context.Context, r *Role) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO roles (id, name, description) VALUES (?, ?, ?)`,
		r.ID, r.Name, r.Description)
	return err
}

func (s *SQLiteStore) UpdateRole(ctx context.Context, id string, name, description string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE roles SET name = ?, description = ? WHERE id = ?`, name, description, id)
	return err
}

func (s *SQLiteStore) DeleteRole(ctx context.Context, id string) error {
	s.db.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = ?`, id)
	s.db.ExecContext(ctx, `DELETE FROM user_roles WHERE role_id = ?`, id)
	_, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, app_type, callbacks, allowed_origins FROM clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var name, appType, callbacks, origins sql.NullString
		if err := rows.Scan(&c.ID, &name, &appType, &callbacks, &origins); err != nil {
			return nil, err
		}
		if name.Valid {
			c.Name = name.String
		}
		if appType.Valid {
			c.AppType = appType.String
		}
		if callbacks.Valid && callbacks.String != "" {
			c.Callbacks = strings.Split(callbacks.String, ",")
			for i := range c.Callbacks {
				c.Callbacks[i] = strings.TrimSpace(c.Callbacks[i])
			}
		}
		if origins.Valid && origins.String != "" {
			c.AllowedOrigins = strings.Split(origins.String, ",")
			for i := range c.AllowedOrigins {
				c.AllowedOrigins[i] = strings.TrimSpace(c.AllowedOrigins[i])
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *SQLiteStore) GetClientByID(ctx context.Context, id string) (*Client, error) {
	var c Client
	var name, appType, callbacks, origins sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, name, app_type, callbacks, allowed_origins FROM clients WHERE id = ?`, id).
		Scan(&c.ID, &name, &appType, &callbacks, &origins)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if name.Valid {
		c.Name = name.String
	}
	if appType.Valid {
		c.AppType = appType.String
	}
	if callbacks.Valid && callbacks.String != "" {
		c.Callbacks = strings.Split(callbacks.String, ",")
		for i := range c.Callbacks {
			c.Callbacks[i] = strings.TrimSpace(c.Callbacks[i])
		}
	}
	if origins.Valid && origins.String != "" {
		c.AllowedOrigins = strings.Split(origins.String, ",")
		for i := range c.AllowedOrigins {
			c.AllowedOrigins[i] = strings.TrimSpace(c.AllowedOrigins[i])
		}
	}
	return &c, nil
}

func (s *SQLiteStore) UpdateClient(ctx context.Context, id string, updates map[string]interface{}) error {
	var set []string
	var args []interface{}
	if v, ok := updates["name"].(string); ok {
		set = append(set, "name = ?")
		args = append(args, v)
	}
	if v, ok := updates["callbacks"].([]string); ok {
		set = append(set, "callbacks = ?")
		args = append(args, strings.Join(v, ","))
	}
	if v, ok := updates["allowed_origins"].([]string); ok {
		set = append(set, "allowed_origins = ?")
		args = append(args, strings.Join(v, ","))
	}
	if v, ok := updates["callbacks"].(string); ok {
		set = append(set, "callbacks = ?")
		args = append(args, v)
	}
	if v, ok := updates["allowed_origins"].(string); ok {
		set = append(set, "allowed_origins = ?")
		args = append(args, v)
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.ExecContext(ctx, `UPDATE clients SET `+strings.Join(set, ", ")+` WHERE id = ?`, args...)
	return err
}

func (s *SQLiteStore) ListConnections(ctx context.Context) ([]Connection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, strategy FROM connections`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var c Connection
		var strategy sql.NullString
		if err := rows.Scan(&c.ID, &c.Name, &strategy); err != nil {
			return nil, err
		}
		if strategy.Valid {
			c.Strategy = strategy.String
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *SQLiteStore) GetConnectionByID(ctx context.Context, id string) (*Connection, error) {
	var c Connection
	var strategy sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, name, strategy FROM connections WHERE id = ?`, id).
		Scan(&c.ID, &c.Name, &strategy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if strategy.Valid {
		c.Strategy = strategy.String
	}
	return &c, nil
}

func (s *SQLiteStore) BlockUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO user_blocks (user_id) VALUES (?)`, userID)
	return err
}

func (s *SQLiteStore) UnblockUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_blocks WHERE user_id = ?`, userID)
	return err
}

func (s *SQLiteStore) IsUserBlocked(ctx context.Context, userID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM user_blocks WHERE user_id = ?`, userID).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *SQLiteStore) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*User, error) {
	var uid string
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM user_identities WHERE provider = ? AND provider_user_id = ?`, provider, providerUserID).Scan(&uid)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetByID(ctx, uid)
}

func (s *SQLiteStore) LinkUserIdentity(ctx context.Context, userID, provider, providerUserID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO user_identities (user_id, provider, provider_user_id) VALUES (?, ?, ?)`, userID, provider, providerUserID)
	return err
}

func (s *SQLiteStore) CreateSAMLServiceProvider(ctx context.Context, sp *SAMLServiceProvider) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO saml_service_providers (id, entity_id, acs_url, certificate, metadata_url) VALUES (?, ?, ?, ?, ?)`,
		sp.ID, sp.EntityID, sp.ACSURL, sp.Certificate, sp.MetadataURL)
	return err
}

func (s *SQLiteStore) GetSAMLServiceProviderByEntityID(ctx context.Context, entityID string) (*SAMLServiceProvider, error) {
	var sp SAMLServiceProvider
	var cert, metaURL sql.NullString
	var createdAt interface{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, entity_id, acs_url, certificate, metadata_url, created_at FROM saml_service_providers WHERE entity_id = ?`,
		entityID).Scan(&sp.ID, &sp.EntityID, &sp.ACSURL, &cert, &metaURL, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if cert.Valid {
		sp.Certificate = cert.String
	}
	if metaURL.Valid {
		sp.MetadataURL = metaURL.String
	}
	return &sp, nil
}

func (s *SQLiteStore) ListSAMLServiceProviders(ctx context.Context) ([]SAMLServiceProvider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, entity_id, acs_url, certificate, metadata_url, created_at FROM saml_service_providers ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SAMLServiceProvider
	for rows.Next() {
		var sp SAMLServiceProvider
		var cert, metaURL sql.NullString
		var createdAt interface{}
		if err := rows.Scan(&sp.ID, &sp.EntityID, &sp.ACSURL, &cert, &metaURL, &createdAt); err != nil {
			return nil, err
		}
		if cert.Valid {
			sp.Certificate = cert.String
		}
		if metaURL.Valid {
			sp.MetadataURL = metaURL.String
		}
		out = append(out, sp)
	}
	return out, nil
}

func (s *SQLiteStore) CreateOIDCEnterpriseConnection(ctx context.Context, ec *OIDCEnterpriseConnection) error {
	scope := ec.Scope
	if scope == "" {
		scope = "openid email profile"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_enterprise_connections (id, name, issuer_url, client_id, client_secret, scope, domain_hint) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ec.ID, ec.Name, ec.IssuerURL, ec.ClientID, ec.ClientSecret, scope, ec.DomainHint)
	return err
}

func (s *SQLiteStore) GetOIDCEnterpriseConnectionByName(ctx context.Context, name string) (*OIDCEnterpriseConnection, error) {
	var ec OIDCEnterpriseConnection
	var scope, domainHint sql.NullString
	var createdAt interface{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, issuer_url, client_id, client_secret, scope, domain_hint, created_at FROM oidc_enterprise_connections WHERE name = ?`,
		name).Scan(&ec.ID, &ec.Name, &ec.IssuerURL, &ec.ClientID, &ec.ClientSecret, &scope, &domainHint, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if scope.Valid {
		ec.Scope = scope.String
	} else {
		ec.Scope = "openid email profile"
	}
	if domainHint.Valid {
		ec.DomainHint = domainHint.String
	}
	return &ec, nil
}

func (s *SQLiteStore) ListOIDCEnterpriseConnections(ctx context.Context) ([]OIDCEnterpriseConnection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, issuer_url, client_id, client_secret, scope, domain_hint, created_at FROM oidc_enterprise_connections ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OIDCEnterpriseConnection
	for rows.Next() {
		var ec OIDCEnterpriseConnection
		var scope, domainHint sql.NullString
		var createdAt interface{}
		if err := rows.Scan(&ec.ID, &ec.Name, &ec.IssuerURL, &ec.ClientID, &ec.ClientSecret, &scope, &domainHint, &createdAt); err != nil {
			return nil, err
		}
		if scope.Valid {
			ec.Scope = scope.String
		} else {
			ec.Scope = "openid email profile"
		}
		if domainHint.Valid {
			ec.DomainHint = domainHint.String
		}
		out = append(out, ec)
	}
	return out, nil
}

func (s *SQLiteStore) GetWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, attestation_type, transports, created_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var credID, pubKey, transports []byte
		var createdAt interface{}
		if err := rows.Scan(&c.ID, &c.UserID, &credID, &pubKey, &c.AttestationType, &transports, &createdAt); err != nil {
			return nil, err
		}
		c.CredentialID = credID
		c.PublicKey = pubKey
		if len(transports) > 0 {
			c.Transports = string(transports)
		}
		if t, ok := parseTimeSQLite(createdAt); ok {
			c.CreatedAt = t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error {
	transports := cred.Transports
	if transports == "" {
		transports = "[]"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, attestation_type, transports, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		cred.ID, cred.UserID, cred.CredentialID, cred.PublicKey, cred.AttestationType, transports, cred.CreatedAt)
	return err
}

func (s *SQLiteStore) UpdatePassword(ctx context.Context, userID string, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, string(hash), userID)
	return err
}

func (s *SQLiteStore) UpdateEmailVerified(ctx context.Context, userID string, verified bool) error {
	v := 0
	if verified {
		v = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET email_verified = ? WHERE id = ?`, v, userID)
	return err
}

func (s *SQLiteStore) CreatePasswordResetToken(ctx context.Context, userID string, expiresAt time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "prt_" + hex.EncodeToString(b)
	_, err := s.db.ExecContext(ctx, `INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)`,
		token, userID, expiresAt.Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *SQLiteStore) ValidatePasswordResetToken(ctx context.Context, token string) (userID string, ok bool) {
	var uid string
	var expiresAt string
	err := s.db.QueryRowContext(ctx, `SELECT user_id, expires_at FROM password_reset_tokens WHERE token = ?`, token).Scan(&uid, &expiresAt)
	if err == sql.ErrNoRows || err != nil {
		return "", false
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		exp, _ = time.Parse("2006-01-02 15:04:05", expiresAt)
	}
	if time.Now().After(exp) {
		return "", false
	}
	return uid, true
}

func (s *SQLiteStore) ConsumePasswordResetToken(ctx context.Context, token string) (userID string, ok bool) {
	var uid string
	var expiresAt string
	err := s.db.QueryRowContext(ctx, `SELECT user_id, expires_at FROM password_reset_tokens WHERE token = ?`, token).Scan(&uid, &expiresAt)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		return "", false
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().After(exp) {
		s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE token = ?`, token)
		return "", false
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE token = ?`, token)
	return uid, true
}

func (s *SQLiteStore) CreateMagicLinkToken(ctx context.Context, data *MagicLinkTokenData) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "magic_" + hex.EncodeToString(b)
	scope := data.Scope
	if scope == "" {
		scope = "openid"
	}
	responseType := data.ResponseType
	if responseType == "" {
		responseType = "code"
	}
	expiresAt := time.Now().Add(1 * time.Hour)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO passwordless_tokens (token, email, client_id, redirect_uri, state, response_type, scope, audience, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token, data.Email, data.ClientID, data.RedirectURI, data.State, responseType, scope, data.Audience, expiresAt.Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *SQLiteStore) ConsumeMagicLinkToken(ctx context.Context, token string) (*MagicLinkTokenData, bool) {
	var email, clientID, redirectURI, state, responseType, scope, audience sql.NullString
	var expiresAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT email, client_id, redirect_uri, state, response_type, scope, audience, expires_at FROM passwordless_tokens WHERE token = ?`,
		token).Scan(&email, &clientID, &redirectURI, &state, &responseType, &scope, &audience, &expiresAt)
	if err == sql.ErrNoRows || err != nil {
		return nil, false
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		exp, _ = time.Parse("2006-01-02 15:04:05", expiresAt)
	}
	if time.Now().After(exp) {
		s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = ?`, token)
		return nil, false
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = ?`, token)
	out := &MagicLinkTokenData{
		Email:        email.String,
		ClientID:     clientID.String,
		RedirectURI:  redirectURI.String,
		State:        state.String,
		ResponseType: responseType.String,
		Scope:        scope.String,
		Audience:     audience.String,
	}
	if out.ResponseType == "" {
		out.ResponseType = "code"
	}
	if out.Scope == "" {
		out.Scope = "openid"
	}
	return out, true
}

func (s *SQLiteStore) RecordFailedLogin(ctx context.Context, identifier string) error {
	maxAttempts := bruteForceMaxAttempts()
	lockoutMin := bruteForceLockoutMinutes()
	var count int
	var lockedUntil sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT attempt_count, locked_until FROM login_attempts WHERE identifier = ?`, identifier).Scan(&count, &lockedUntil)
	if err == sql.ErrNoRows {
		var lockedUntilVal interface{} = nil
		if maxAttempts <= 1 {
			lockedUntilVal = time.Now().Add(time.Duration(lockoutMin) * time.Minute).Format("2006-01-02 15:04:05")
		}
		_, err = s.db.ExecContext(ctx, `INSERT INTO login_attempts (identifier, attempt_count, locked_until, updated_at) VALUES (?, 1, ?, CURRENT_TIMESTAMP)`,
			identifier, lockedUntilVal)
		return err
	}
	if err != nil {
		return err
	}
	count++
	lockedUntilStr := lockedUntil.String
	if count >= maxAttempts {
		lockedUntilStr = time.Now().Add(time.Duration(lockoutMin) * time.Minute).Format("2006-01-02 15:04:05")
	}
	var lockedUntilVal interface{} = nil
	if lockedUntilStr != "" {
		lockedUntilVal = lockedUntilStr
	}
	_, err = s.db.ExecContext(ctx, `UPDATE login_attempts SET attempt_count = ?, locked_until = ?, updated_at = CURRENT_TIMESTAMP WHERE identifier = ?`,
		count, lockedUntilVal, identifier)
	return err
}

func bruteForceMaxAttempts() int {
	if v := os.Getenv("BRUTE_FORCE_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 5
}

func bruteForceLockoutMinutes() int {
	if v := os.Getenv("BRUTE_FORCE_LOCKOUT_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 15
}

func (s *SQLiteStore) ClearFailedLogins(ctx context.Context, identifier string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE identifier = ?`, identifier)
	return err
}

func (s *SQLiteStore) IsLockedOut(ctx context.Context, identifier string) (time.Time, bool) {
	var lockedUntil sql.NullString
	var attemptCount int
	err := s.db.QueryRowContext(ctx, `SELECT locked_until, attempt_count FROM login_attempts WHERE identifier = ?`, identifier).Scan(&lockedUntil, &attemptCount)
	if err == sql.ErrNoRows {
		return time.Time{}, false
	}
	if err != nil {
		return time.Time{}, false
	}
	if !lockedUntil.Valid || lockedUntil.String == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02 15:04:05", lockedUntil.String)
	if err != nil {
		t, _ = time.Parse(time.RFC3339, lockedUntil.String)
	}
	if time.Now().Before(t) {
		return t, true
	}
	// Lock expired - clear it
	s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE identifier = ?`, identifier)
	return time.Time{}, false
}

func (s *SQLiteStore) AppendLog(ctx context.Context, eventType, userID, clientID, payload string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_logs (event_type, user_id, client_id, payload) VALUES (?, ?, ?, ?)`,
		eventType, userID, clientID, payload)
	return err
}

func (s *SQLiteStore) ListLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, event_type, user_id, client_id, payload, created_at FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditLog
	for rows.Next() {
		var l AuditLog
		var userID, clientID, payload sql.NullString
		var createdAt interface{}
		if err := rows.Scan(&l.ID, &l.EventType, &userID, &clientID, &payload, &createdAt); err != nil {
			return nil, err
		}
		if userID.Valid {
			l.UserID = userID.String
		}
		if clientID.Valid {
			l.ClientID = clientID.String
		}
		if payload.Valid {
			l.Payload = payload.String
		}
		out = append(out, l)
	}
	return out, nil
}

func (s *SQLiteStore) DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE created_at < ?`, olderThan.Format("2006-01-02 15:04:05"))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SQLiteStore) ListUsersExport(ctx context.Context, page, perPage int) ([]ExportUser, int, error) {
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 100 {
		perPage = 100
	}
	offset := page * perPage

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, display_name, COALESCE(email_verified, 0), created_at, app_metadata, user_metadata 
		 FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ExportUser
	for rows.Next() {
		var u ExportUser
		var name sql.NullString
		var createdAt interface{}
		var emailVerified int
		var appMeta, userMeta sql.NullString
		if err := rows.Scan(&u.UserID, &u.Email, &name, &emailVerified, &createdAt, &appMeta, &userMeta); err != nil {
			return nil, 0, err
		}
		u.EmailVerified = emailVerified != 0
		if name.Valid {
			u.Name = name.String
		}
		if t, ok := parseTimeSQLite(createdAt); ok {
			u.CreatedAt = t
		}
		u.AppMetadata = parseJSONMap(appMeta)
		u.UserMetadata = parseJSONMap(userMeta)
		out = append(out, u)
	}

	var total int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&total)
	return out, total, nil
}

func parseTimeSQLite(v interface{}) (time.Time, bool) {
	if v == nil {
		return time.Time{}, false
	}
	switch t := v.(type) {
	case time.Time:
		return t, true
	case string:
		parsed, err := time.Parse("2006-01-02 15:04:05", t)
		if err != nil {
			parsed, err = time.Parse(time.RFC3339, t)
		}
		return parsed, err == nil
	}
	return time.Time{}, false
}

func (s *SQLiteStore) GetMFAEnrollment(ctx context.Context, userID string) (*MFAEnrollment, error) {
	var totpSecret, backupCodesJSON sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT totp_secret, backup_codes_hash FROM mfa_enrollment WHERE user_id = ?`, userID).
		Scan(&totpSecret, &backupCodesJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	en := &MFAEnrollment{UserID: userID, TOTPSecret: totpSecret.String}
	if backupCodesJSON.Valid && backupCodesJSON.String != "" {
		if err := json.Unmarshal([]byte(backupCodesJSON.String), &en.BackupCodeHashes); err != nil {
			return nil, err
		}
	}
	return en, nil
}

func (s *SQLiteStore) SetMFAEnrollment(ctx context.Context, userID, totpSecret string, backupCodeHashes []string) error {
	hashesJSON := "[]"
	if len(backupCodeHashes) > 0 {
		b, err := json.Marshal(backupCodeHashes)
		if err != nil {
			return err
		}
		hashesJSON = string(b)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO mfa_enrollment (user_id, totp_secret, backup_codes_hash) VALUES (?, ?, ?)
		 ON CONFLICT (user_id) DO UPDATE SET totp_secret = excluded.totp_secret, backup_codes_hash = excluded.backup_codes_hash`,
		userID, totpSecret, hashesJSON)
	return err
}

func (s *SQLiteStore) AddKnownIP(ctx context.Context, userID, ip string) error {
	if userID == "" || ip == "" {
		return nil
	}
	now := time.Now().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_known_ips (user_id, ip, last_seen) VALUES (?, ?, ?) ON CONFLICT (user_id, ip) DO UPDATE SET last_seen = excluded.last_seen`,
		userID, ip, now)
	return err
}

func (s *SQLiteStore) IsIPKnownForUser(ctx context.Context, userID, ip string) (bool, error) {
	if userID == "" || ip == "" {
		return false, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM user_known_ips WHERE user_id = ? AND ip = ?`, userID, ip).Scan(&count)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) CreateSMSOTPToken(ctx context.Context, data *SMSOTPTokenData) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "sms_" + hex.EncodeToString(b)
	scope := data.Scope
	if scope == "" {
		scope = "openid"
	}
	responseType := data.ResponseType
	if responseType == "" {
		responseType = "code"
	}
	expiresAt := time.Now().Add(10 * time.Minute)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO passwordless_tokens (token, token_type, phone, code, email, client_id, redirect_uri, state, response_type, scope, audience, expires_at) VALUES (?, 'sms', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token, data.Phone, data.Code, "sms:"+data.Phone, data.ClientID, data.RedirectURI, data.State, responseType, scope, data.Audience, expiresAt.Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *SQLiteStore) ConsumeSMSOTPToken(ctx context.Context, token, code string) (*SMSOTPTokenData, bool) {
	if !strings.HasPrefix(token, "sms_") {
		return nil, false
	}
	var phone, clientID, redirectURI, state, responseType, scope, audience sql.NullString
	var storedCode sql.NullString
	var expiresAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT phone, code, client_id, redirect_uri, state, response_type, scope, audience, expires_at FROM passwordless_tokens WHERE token = ? AND token_type = 'sms'`,
		token).Scan(&phone, &storedCode, &clientID, &redirectURI, &state, &responseType, &scope, &audience, &expiresAt)
	if err == sql.ErrNoRows || err != nil {
		return nil, false
	}
	if !storedCode.Valid || storedCode.String != code {
		s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = ?`, token)
		return nil, false
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		exp, _ = time.Parse("2006-01-02 15:04:05", expiresAt)
	}
	if time.Now().After(exp) {
		s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = ?`, token)
		return nil, false
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = ?`, token)
	out := &SMSOTPTokenData{
		Phone:        phone.String,
		ClientID:     clientID.String,
		RedirectURI:  redirectURI.String,
		State:        state.String,
		ResponseType: responseType.String,
		Scope:        scope.String,
		Audience:     audience.String,
	}
	if out.ResponseType == "" {
		out.ResponseType = "code"
	}
	if out.Scope == "" {
		out.Scope = "openid"
	}
	return out, true
}

func (s *SQLiteStore) ConsumeBackupCode(ctx context.Context, userID, code string) (bool, error) {
	en, err := s.GetMFAEnrollment(ctx, userID)
	if err != nil || en == nil || len(en.BackupCodeHashes) == 0 {
		return false, err
	}
	valid, idx := mfa.VerifyBackupCode(code, en.BackupCodeHashes)
	if !valid {
		return false, nil
	}
	// Remove consumed hash
	hashes := make([]string, 0, len(en.BackupCodeHashes)-1)
	for i, h := range en.BackupCodeHashes {
		if i != idx {
			hashes = append(hashes, h)
		}
	}
	hashesJSON := "[]"
	if len(hashes) > 0 {
		b, _ := json.Marshal(hashes)
		hashesJSON = string(b)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE mfa_enrollment SET backup_codes_hash = ? WHERE user_id = ?`, hashesJSON, userID)
	return err == nil, err
}

// Organizations

func (s *SQLiteStore) CreateOrganization(ctx context.Context, org *Organization) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO organizations (id, name, display_name, metadata) VALUES (?, ?, ?, ?)`,
		org.ID, org.Name, org.DisplayName, jsonBytes(org.Metadata))
	return err
}

func (s *SQLiteStore) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	var o Organization
	var displayName, meta sql.NullString
	var createdAt string
	err := s.db.QueryRowContext(ctx, `SELECT id, name, display_name, metadata, created_at FROM organizations WHERE id = ?`, id).
		Scan(&o.ID, &o.Name, &displayName, &meta, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if displayName.Valid {
		o.DisplayName = displayName.String
	}
	o.Metadata = parseJSONMap(meta)
	if t, ok := parseTimeSQLite(createdAt); ok {
		o.CreatedAt = t
	}
	return &o, nil
}

func (s *SQLiteStore) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, display_name, metadata, created_at FROM organizations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		var displayName, meta sql.NullString
		var createdAt string
		if err := rows.Scan(&o.ID, &o.Name, &displayName, &meta, &createdAt); err != nil {
			return nil, err
		}
		if displayName.Valid {
			o.DisplayName = displayName.String
		}
		o.Metadata = parseJSONMap(meta)
		if t, ok := parseTimeSQLite(createdAt); ok {
			o.CreatedAt = t
		}
		out = append(out, o)
	}
	return out, nil
}

func (s *SQLiteStore) UpdateOrganization(ctx context.Context, id string, updates map[string]interface{}) error {
	var set []string
	var args []interface{}
	if v, ok := updates["name"].(string); ok {
		set = append(set, "name = ?")
		args = append(args, v)
	}
	if v, ok := updates["display_name"].(string); ok {
		set = append(set, "display_name = ?")
		args = append(args, v)
	}
	if v, ok := updates["metadata"].(map[string]interface{}); ok {
		set = append(set, "metadata = ?")
		args = append(args, jsonBytes(v))
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.ExecContext(ctx, `UPDATE organizations SET `+strings.Join(set, ", ")+` WHERE id = ?`, args...)
	return err
}

func (s *SQLiteStore) DeleteOrganization(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM organizations WHERE id = ?`, id)
	return err
}

func (s *SQLiteStore) AddOrgMember(ctx context.Context, orgID, userID, role string) error {
	if role == "" {
		role = "member"
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO org_members (org_id, user_id, role) VALUES (?, ?, ?)`, orgID, userID, role)
	return err
}

func (s *SQLiteStore) RemoveOrgMember(ctx context.Context, orgID, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM org_members WHERE org_id = ? AND user_id = ?`, orgID, userID)
	return err
}

func (s *SQLiteStore) ListOrgMembers(ctx context.Context, orgID string) ([]OrgMember, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT org_id, user_id, role FROM org_members WHERE org_id = ?`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgMember
	for rows.Next() {
		var m OrgMember
		if err := rows.Scan(&m.OrgID, &m.UserID, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (s *SQLiteStore) IsOrgMember(ctx context.Context, orgID, userID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM org_members WHERE org_id = ? AND user_id = ?`, orgID, userID).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *SQLiteStore) SetOrgConnection(ctx context.Context, orgID, connectionID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO org_connections (org_id, connection_id) VALUES (?, ?)`, orgID, connectionID)
	return err
}

func (s *SQLiteStore) ListOrgConnections(ctx context.Context, orgID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT connection_id FROM org_connections WHERE org_id = ?`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			return nil, err
		}
		out = append(out, cid)
	}
	return out, nil
}

func (s *SQLiteStore) RemoveOrgConnection(ctx context.Context, orgID, connectionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM org_connections WHERE org_id = ? AND connection_id = ?`, orgID, connectionID)
	return err
}

func (s *SQLiteStore) CreateEnterpriseConnection(ctx context.Context, ec *EnterpriseConnection) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO enterprise_connections (id, org_id, name, domain_hint, issuer_url, client_id, client_secret) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ec.ID, ec.OrgID, ec.Name, ec.DomainHint, ec.IssuerURL, ec.ClientID, ec.ClientSecret)
	return err
}

func (s *SQLiteStore) GetEnterpriseConnection(ctx context.Context, id string) (*EnterpriseConnection, error) {
	var ec EnterpriseConnection
	var domainHint, secret sql.NullString
	var createdAt string
	err := s.db.QueryRowContext(ctx, `SELECT id, org_id, name, domain_hint, issuer_url, client_id, client_secret, created_at FROM enterprise_connections WHERE id = ?`, id).
		Scan(&ec.ID, &ec.OrgID, &ec.Name, &domainHint, &ec.IssuerURL, &ec.ClientID, &secret, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if domainHint.Valid {
		ec.DomainHint = domainHint.String
	}
	if secret.Valid {
		ec.ClientSecret = secret.String
	}
	if t, ok := parseTimeSQLite(createdAt); ok {
		ec.CreatedAt = t
	}
	return &ec, nil
}

func (s *SQLiteStore) ListEnterpriseConnections(ctx context.Context, orgID string) ([]EnterpriseConnection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, org_id, name, domain_hint, issuer_url, client_id, client_secret, created_at FROM enterprise_connections WHERE org_id = ?`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnterpriseConnection
	for rows.Next() {
		var ec EnterpriseConnection
		var domainHint, secret sql.NullString
		var createdAt string
		if err := rows.Scan(&ec.ID, &ec.OrgID, &ec.Name, &domainHint, &ec.IssuerURL, &ec.ClientID, &secret, &createdAt); err != nil {
			return nil, err
		}
		if domainHint.Valid {
			ec.DomainHint = domainHint.String
		}
		if secret.Valid {
			ec.ClientSecret = secret.String
		}
		if t, ok := parseTimeSQLite(createdAt); ok {
			ec.CreatedAt = t
		}
		out = append(out, ec)
	}
	return out, nil
}

func (s *SQLiteStore) GetEnterpriseConnectionByDomain(ctx context.Context, domain string) (*EnterpriseConnection, error) {
	var ec EnterpriseConnection
	var domainHint, secret sql.NullString
	var createdAt string
	err := s.db.QueryRowContext(ctx, `SELECT id, org_id, name, domain_hint, issuer_url, client_id, client_secret, created_at FROM enterprise_connections WHERE LOWER(domain_hint) = LOWER(?)`, domain).
		Scan(&ec.ID, &ec.OrgID, &ec.Name, &domainHint, &ec.IssuerURL, &ec.ClientID, &secret, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if domainHint.Valid {
		ec.DomainHint = domainHint.String
	}
	if secret.Valid {
		ec.ClientSecret = secret.String
	}
	if t, ok := parseTimeSQLite(createdAt); ok {
		ec.CreatedAt = t
	}
	return &ec, nil
}

func (s *SQLiteStore) CreateInvitation(ctx context.Context, inv *Invitation) (string, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO invitations (id, org_id, email, role, token, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		inv.ID, inv.OrgID, inv.Email, inv.Role, inv.Token, inv.ExpiresAt.Format(time.RFC3339))
	return inv.Token, err
}

func (s *SQLiteStore) GetInvitationByToken(ctx context.Context, token string) (*Invitation, error) {
	var inv Invitation
	var expiresAt, createdAt string
	err := s.db.QueryRowContext(ctx, `SELECT id, org_id, email, role, token, expires_at, created_at FROM invitations WHERE token = ?`, token).
		Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.Token, &expiresAt, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if t, ok := parseTimeSQLite(expiresAt); ok && time.Now().After(t) {
		return nil, nil
	}
	if t, ok := parseTimeSQLite(expiresAt); ok {
		inv.ExpiresAt = t
	}
	if t, ok := parseTimeSQLite(createdAt); ok {
		inv.CreatedAt = t
	}
	return &inv, nil
}

func (s *SQLiteStore) ConsumeInvitation(ctx context.Context, token string) (*Invitation, bool) {
	inv, err := s.GetInvitationByToken(ctx, token)
	if err != nil || inv == nil {
		return nil, false
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM invitations WHERE token = ?`, token)
	if err != nil {
		return nil, false
	}
	return inv, true
}

func (s *SQLiteStore) SaveCIBARequest(ctx context.Context, req *CIBARequest) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ciba_requests (auth_req_id, client_id, login_hint, scope, audience, status, user_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		req.AuthReqID, req.ClientID, req.LoginHint, req.Scope, req.Audience, req.Status, req.UserID, req.ExpiresAt)
	return err
}

func (s *SQLiteStore) GetCIBARequest(ctx context.Context, authReqID string) (*CIBARequest, error) {
	var req CIBARequest
	var expiresAt, createdAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT auth_req_id, client_id, login_hint, scope, audience, status, user_id, created_at, expires_at FROM ciba_requests WHERE auth_req_id = ?`,
		authReqID,
	).Scan(&req.AuthReqID, &req.ClientID, &req.LoginHint, &req.Scope, &req.Audience, &req.Status, &req.UserID, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if t, ok := parseTimeSQLite(expiresAt); ok && time.Now().After(t) {
		return nil, nil
	}
	if t, ok := parseTimeSQLite(expiresAt); ok {
		req.ExpiresAt = t
	}
	if t, ok := parseTimeSQLite(createdAt); ok {
		req.CreatedAt = t
	}
	return &req, nil
}

func (s *SQLiteStore) UpdateCIBARequestStatus(ctx context.Context, authReqID, status, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE ciba_requests SET status = ?, user_id = ? WHERE auth_req_id = ?`,
		status, userID, authReqID)
	return err
}

func (s *SQLiteStore) SaveTokenVaultEntry(ctx context.Context, entry *TokenVaultEntry) (string, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE token_vault SET access_token_encrypted = ?, metadata = ? WHERE name = ? AND user_id = ?`,
		entry.AccessTokenEncrypted, entry.Metadata, entry.Name, entry.UserID)
	if err != nil {
		return "", err
	}
	aff, _ := res.RowsAffected()
	if aff > 0 {
		var id string
		_ = s.db.QueryRowContext(ctx, `SELECT id FROM token_vault WHERE name = ? AND user_id = ?`, entry.Name, entry.UserID).Scan(&id)
		return id, nil
	}
	if entry.ID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err == nil {
			entry.ID = "vault_" + hex.EncodeToString(b)
		} else {
			entry.ID = "vault_" + hex.EncodeToString(make([]byte, 8))
		}
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO token_vault (id, name, user_id, access_token_encrypted, metadata) VALUES (?, ?, ?, ?, ?)`,
		entry.ID, entry.Name, entry.UserID, entry.AccessTokenEncrypted, entry.Metadata)
	return entry.ID, err
}

func (s *SQLiteStore) GetTokenVaultEntry(ctx context.Context, name, userID string) (*TokenVaultEntry, error) {
	var e TokenVaultEntry
	var createdAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, user_id, access_token_encrypted, metadata, created_at FROM token_vault WHERE name = ? AND user_id = ?`,
		name, userID,
	).Scan(&e.ID, &e.Name, &e.UserID, &e.AccessTokenEncrypted, &e.Metadata, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if t, ok := parseTimeSQLite(createdAt); ok {
		e.CreatedAt = t
	}
	return &e, nil
}

func (s *SQLiteStore) GetTokenVaultEntryByID(ctx context.Context, id string) (*TokenVaultEntry, error) {
	var e TokenVaultEntry
	var createdAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, user_id, access_token_encrypted, metadata, created_at FROM token_vault WHERE id = ?`,
		id,
	).Scan(&e.ID, &e.Name, &e.UserID, &e.AccessTokenEncrypted, &e.Metadata, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if t, ok := parseTimeSQLite(createdAt); ok {
		e.CreatedAt = t
	}
	return &e, nil
}
