package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

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
	`)
	if err != nil {
		return err
	}
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
		INSERT OR IGNORE INTO clients (id, name, app_type, callbacks, allowed_origins) VALUES ('radimal-e2e', 'Radimal E2E', 'spa', 'http://localhost:3000/callback,http://localhost/callback', 'http://localhost:3000,http://localhost');
		INSERT OR IGNORE INTO clients (id, name, app_type, callbacks, allowed_origins) VALUES ('default', 'auth0', 'regular_web', 'http://localhost/callback', '');
		INSERT OR IGNORE INTO connections (id, name, strategy) VALUES ('con_db_main', 'Username-Password-Authentication', 'auth0');
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
	var role, appMeta, userMeta sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, organization_id, enterprise_id, role, app_metadata, user_metadata FROM users WHERE email = ?`,
		email,
	).Scan(&id, &em, &hash, &displayName, &orgID, &entID, &role, &appMeta, &userMeta)
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
	u.AppMetadata = parseJSONMap(appMeta)
	u.UserMetadata = parseJSONMap(userMeta)
	return u, nil
}

func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*User, error) {
	var uid, em, hash, displayName string
	var orgID, entID int
	var role, appMeta, userMeta sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, organization_id, enterprise_id, role, app_metadata, user_metadata FROM users WHERE id = ?`,
		id,
	).Scan(&uid, &em, &hash, &displayName, &orgID, &entID, &role, &appMeta, &userMeta)
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
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, display_name, organization_id, enterprise_id, role, app_metadata, user_metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.PasswordHash, u.DisplayName, u.OrganizationID, u.EnterpriseID, u.Role, jsonBytes(u.AppMetadata), jsonBytes(u.UserMetadata),
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

type ListUsersOpts struct {
	Page    int
	PerPage int
	Query   string // simple search: email or display_name contains
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
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.ExecContext(ctx, `UPDATE users SET `+strings.Join(set, ", ")+` WHERE id = ?`, args...)
	return err
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ?`, id)
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

type Client struct {
	ID             string
	Name           string
	AppType        string
	Callbacks      []string
	AllowedOrigins []string
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

type Connection struct {
	ID       string
	Name     string
	Strategy string
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

type AuditLog struct {
	ID        int64
	EventType string
	UserID    string
	ClientID  string
	Payload   string
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
