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

	_ "github.com/jackc/pgx/v5/stdlib"
)


type PostgresStore struct {
	db *sql.DB
}

// NewPostgres creates a new PostgresStore. Call MigratePostgres before use if schema is not applied.
func NewPostgres(dsn string, maxOpen, maxIdle int) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if maxOpen > 0 {
		db.SetMaxOpenConns(maxOpen)
	}
	if maxIdle > 0 {
		db.SetMaxIdleConns(maxIdle)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// DB returns the underlying *sql.DB for migrations.
func (s *PostgresStore) DB() *sql.DB {
	return s.db
}

func (s *PostgresStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *PostgresStore) VerifyPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (s *PostgresStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	var id, em, hash, displayName string
	var orgID, entID int
	var emailVerified bool
	var role, appMeta, userMeta, phoneNum sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, COALESCE(email_verified, false), organization_id, enterprise_id, role, app_metadata, user_metadata, phone_number FROM users WHERE email = $1`,
		email,
	).Scan(&id, &em, &hash, &displayName, &emailVerified, &orgID, &entID, &role, &appMeta, &userMeta, &phoneNum)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u := &User{ID: id, Email: em, PasswordHash: hash, DisplayName: displayName, EmailVerified: emailVerified, OrganizationID: orgID, EnterpriseID: entID}
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

func (s *PostgresStore) GetByPhone(ctx context.Context, phone string) (*User, error) {
	if phone == "" {
		return nil, nil
	}
	var id, em, hash, displayName string
	var orgID, entID int
	var emailVerified bool
	var role, appMeta, userMeta, phoneNum sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, COALESCE(email_verified, false), organization_id, enterprise_id, role, app_metadata, user_metadata, phone_number FROM users WHERE phone_number = $1`,
		phone,
	).Scan(&id, &em, &hash, &displayName, &emailVerified, &orgID, &entID, &role, &appMeta, &userMeta, &phoneNum)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u := &User{ID: id, Email: em, PasswordHash: hash, DisplayName: displayName, EmailVerified: emailVerified, OrganizationID: orgID, EnterpriseID: entID}
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

func (s *PostgresStore) GetByID(ctx context.Context, id string) (*User, error) {
	var uid, em, hash, displayName string
	var orgID, entID int
	var emailVerified bool
	var role, appMeta, userMeta, phoneNum sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, display_name, COALESCE(email_verified, false), organization_id, enterprise_id, role, app_metadata, user_metadata, phone_number FROM users WHERE id = $1`,
		id,
	).Scan(&uid, &em, &hash, &displayName, &emailVerified, &orgID, &entID, &role, &appMeta, &userMeta, &phoneNum)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u := &User{ID: uid, Email: em, PasswordHash: hash, DisplayName: displayName, EmailVerified: emailVerified, OrganizationID: orgID, EnterpriseID: entID}
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

func (s *PostgresStore) Create(ctx context.Context, u *User) error {
	return s.CreateUser(ctx, u, u.PasswordHash)
}

func (s *PostgresStore) UpdateAppMetadata(ctx context.Context, id string, meta map[string]interface{}) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET app_metadata = $1 WHERE id = $2`, string(b), id)
	return err
}

func (s *PostgresStore) CreateUser(ctx context.Context, u *User, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, display_name, email_verified, organization_id, enterprise_id, role, app_metadata, user_metadata, phone_number) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		u.ID, u.Email, u.PasswordHash, u.DisplayName, u.EmailVerified, u.OrganizationID, u.EnterpriseID, u.Role, jsonBytes(u.AppMetadata), jsonBytes(u.UserMetadata), u.PhoneNumber,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	roleID := "rol_default"
	if u.Role == "admin" {
		roleID = "rol_admin"
	}
	s.db.ExecContext(ctx, `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING`, u.ID, roleID)
	return nil
}

func (s *PostgresStore) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.name, r.description FROM roles r
		 JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = $1`, userID)
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

func (s *PostgresStore) GetUserPermissions(ctx context.Context, userID string) ([]Permission, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT p.id, p.name, p.resource_server_identifier, p.description
		 FROM permissions p
		 JOIN role_permissions rp ON rp.permission_id = p.id
		 JOIN user_roles ur ON ur.role_id = rp.role_id
		 WHERE ur.user_id = $1`, userID)
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

func (s *PostgresStore) ListRoles(ctx context.Context) ([]Role, error) {
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

func (s *PostgresStore) AssignRoleToUser(ctx context.Context, userID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING`, userID, roleID)
	return err
}

func (s *PostgresStore) RemoveRoleFromUser(ctx context.Context, userID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`, userID, roleID)
	return err
}

func (s *PostgresStore) ListUsers(ctx context.Context, opts ListUsersOpts) ([]User, int, error) {
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
			 WHERE email ILIKE $1 OR display_name ILIKE $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
			pattern, pattern, opts.PerPage, offset)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, email, password_hash, display_name, organization_id, enterprise_id, role FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
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
		s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE email ILIKE $1 OR display_name ILIKE $2`, pattern, pattern).Scan(&total)
	} else {
		s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&total)
	}
	return users, total, nil
}

func (s *PostgresStore) UpdateUser(ctx context.Context, id string, updates map[string]interface{}) error {
	var set []string
	var args []interface{}
	n := 1
	if v, ok := updates["email"].(string); ok {
		set = append(set, fmt.Sprintf("email = $%d", n))
		args = append(args, v)
		n++
	}
	if v, ok := updates["name"].(string); ok {
		set = append(set, fmt.Sprintf("display_name = $%d", n))
		args = append(args, v)
		n++
	}
	if v, ok := updates["display_name"].(string); ok {
		set = append(set, fmt.Sprintf("display_name = $%d", n))
		args = append(args, v)
		n++
	}
	if v, ok := updates["user_metadata"].(map[string]interface{}); ok {
		set = append(set, fmt.Sprintf("user_metadata = $%d", n))
		args = append(args, jsonBytes(v))
		n++
	}
	if v, ok := updates["app_metadata"].(map[string]interface{}); ok {
		set = append(set, fmt.Sprintf("app_metadata = $%d", n))
		args = append(args, jsonBytes(v))
		n++
	}
	if v, ok := updates["email_verified"].(bool); ok {
		set = append(set, fmt.Sprintf("email_verified = $%d", n))
		args = append(args, v)
		n++
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.ExecContext(ctx, `UPDATE users SET `+strings.Join(set, ", ")+` WHERE id = $`+fmt.Sprint(n), args...)
	return err
}


func (s *PostgresStore) UpdatePassword(ctx context.Context, userID string, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, string(hash), userID)
	return err
}

func (s *PostgresStore) UpdateEmailVerified(ctx context.Context, userID string, verified bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET email_verified = $1 WHERE id = $2`, verified, userID)
	return err
}

func (s *PostgresStore) CreatePasswordResetToken(ctx context.Context, userID string, expiresAt time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "prt_" + hex.EncodeToString(b)
	_, err := s.db.ExecContext(ctx, `INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)`,
		token, userID, expiresAt)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *PostgresStore) ValidatePasswordResetToken(ctx context.Context, token string) (userID string, ok bool) {
	var uid string
	var expiresAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT user_id, expires_at FROM password_reset_tokens WHERE token = $1`, token).Scan(&uid, &expiresAt)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		return "", false
	}
	if time.Now().After(expiresAt) {
		return "", false
	}
	return uid, true
}

func (s *PostgresStore) ConsumePasswordResetToken(ctx context.Context, token string) (userID string, ok bool) {
	var uid string
	var expiresAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT user_id, expires_at FROM password_reset_tokens WHERE token = $1`, token).Scan(&uid, &expiresAt)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		return "", false
	}
	if time.Now().After(expiresAt) {
		s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE token = $1`, token)
		return "", false
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE token = $1`, token)
	return uid, true
}

func (s *PostgresStore) CreateMagicLinkToken(ctx context.Context, data *MagicLinkTokenData) (string, error) {
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
		`INSERT INTO passwordless_tokens (token, email, client_id, redirect_uri, state, response_type, scope, audience, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		token, data.Email, data.ClientID, data.RedirectURI, data.State, responseType, scope, data.Audience, expiresAt)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *PostgresStore) ConsumeMagicLinkToken(ctx context.Context, token string) (*MagicLinkTokenData, bool) {
	var email, clientID, redirectURI, state, responseType, scope, audience sql.NullString
	var expiresAt time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT email, client_id, redirect_uri, state, response_type, scope, audience, expires_at FROM passwordless_tokens WHERE token = $1`,
		token).Scan(&email, &clientID, &redirectURI, &state, &responseType, &scope, &audience, &expiresAt)
	if err == sql.ErrNoRows || err != nil {
		return nil, false
	}
	if time.Now().After(expiresAt) {
		s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = $1`, token)
		return nil, false
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = $1`, token)
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

func (s *PostgresStore) RecordFailedLogin(ctx context.Context, identifier string) error {
	maxAttempts := postgresBruteForceMaxAttempts()
	lockoutMin := postgresBruteForceLockoutMinutes()
	var count int
	var lockedUntil sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT attempt_count, locked_until FROM login_attempts WHERE identifier = $1`, identifier).Scan(&count, &lockedUntil)
	if err == sql.ErrNoRows {
		var lockedUntilVal interface{} = nil
		if maxAttempts <= 1 {
			lockedUntilVal = time.Now().Add(time.Duration(lockoutMin) * time.Minute)
		}
		_, err = s.db.ExecContext(ctx, `INSERT INTO login_attempts (identifier, attempt_count, locked_until, updated_at) VALUES ($1, 1, $2, CURRENT_TIMESTAMP)`,
			identifier, lockedUntilVal)
		return err
	}
	if err != nil {
		return err
	}
	count++
	var lockedUntilVal interface{} = nil
	if count >= maxAttempts {
		lockedUntilVal = time.Now().Add(time.Duration(lockoutMin) * time.Minute)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE login_attempts SET attempt_count = $1, locked_until = $2, updated_at = CURRENT_TIMESTAMP WHERE identifier = $3`,
		count, lockedUntilVal, identifier)
	return err
}

func (s *PostgresStore) ClearFailedLogins(ctx context.Context, identifier string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE identifier = $1`, identifier)
	return err
}

func (s *PostgresStore) IsLockedOut(ctx context.Context, identifier string) (time.Time, bool) {
	var lockedUntil sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT locked_until FROM login_attempts WHERE identifier = $1`, identifier).Scan(&lockedUntil)
	if err == sql.ErrNoRows || !lockedUntil.Valid {
		return time.Time{}, false
	}
	if err != nil {
		return time.Time{}, false
	}
	if time.Now().Before(lockedUntil.Time) {
		return lockedUntil.Time, true
	}
	s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE identifier = $1`, identifier)
	return time.Time{}, false
}

func postgresBruteForceMaxAttempts() int {
	if v := os.Getenv("BRUTE_FORCE_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 5
}

func postgresBruteForceLockoutMinutes() int {
	if v := os.Getenv("BRUTE_FORCE_LOCKOUT_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 15
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM user_identities WHERE user_id = $1`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM mfa_enrollment WHERE user_id = $1`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = $1`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM user_blocks WHERE user_id = $1`, id)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func (s *PostgresStore) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	var r Role
	var desc sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, name, description FROM roles WHERE id = $1`, id).
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

func (s *PostgresStore) CreateRole(ctx context.Context, r *Role) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO roles (id, name, description) VALUES ($1, $2, $3)`,
		r.ID, r.Name, r.Description)
	return err
}

func (s *PostgresStore) UpdateRole(ctx context.Context, id string, name, description string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE roles SET name = $1, description = $2 WHERE id = $3`, name, description, id)
	return err
}

func (s *PostgresStore) DeleteRole(ctx context.Context, id string) error {
	s.db.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, id)
	s.db.ExecContext(ctx, `DELETE FROM user_roles WHERE role_id = $1`, id)
	_, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, id)
	return err
}

func (s *PostgresStore) ListClients(ctx context.Context) ([]Client, error) {
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

func (s *PostgresStore) GetClientByID(ctx context.Context, id string) (*Client, error) {
	var c Client
	var name, appType, callbacks, origins sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, name, app_type, callbacks, allowed_origins FROM clients WHERE id = $1`, id).
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

func (s *PostgresStore) UpdateClient(ctx context.Context, id string, updates map[string]interface{}) error {
	var set []string
	var args []interface{}
	n := 1
	if v, ok := updates["name"].(string); ok {
		set = append(set, fmt.Sprintf("name = $%d", n))
		args = append(args, v)
		n++
	}
	if v, ok := updates["callbacks"].([]string); ok {
		set = append(set, fmt.Sprintf("callbacks = $%d", n))
		args = append(args, strings.Join(v, ","))
		n++
	}
	if v, ok := updates["allowed_origins"].([]string); ok {
		set = append(set, fmt.Sprintf("allowed_origins = $%d", n))
		args = append(args, strings.Join(v, ","))
		n++
	}
	if v, ok := updates["callbacks"].(string); ok {
		set = append(set, fmt.Sprintf("callbacks = $%d", n))
		args = append(args, v)
		n++
	}
	if v, ok := updates["allowed_origins"].(string); ok {
		set = append(set, fmt.Sprintf("allowed_origins = $%d", n))
		args = append(args, v)
		n++
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.ExecContext(ctx, `UPDATE clients SET `+strings.Join(set, ", ")+` WHERE id = $`+fmt.Sprint(n), args...)
	return err
}

func (s *PostgresStore) ListConnections(ctx context.Context) ([]Connection, error) {
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

func (s *PostgresStore) GetConnectionByID(ctx context.Context, id string) (*Connection, error) {
	var c Connection
	var strategy sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, name, strategy FROM connections WHERE id = $1`, id).
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

func (s *PostgresStore) BlockUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_blocks (user_id) VALUES ($1) ON CONFLICT (user_id) DO UPDATE SET blocked_at = CURRENT_TIMESTAMP`, userID)
	return err
}

func (s *PostgresStore) UnblockUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM user_blocks WHERE user_id = $1`, userID)
	return err
}

func (s *PostgresStore) IsUserBlocked(ctx context.Context, userID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM user_blocks WHERE user_id = $1`, userID).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *PostgresStore) GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*User, error) {
	var uid string
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM user_identities WHERE provider = $1 AND provider_user_id = $2`, provider, providerUserID).Scan(&uid)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetByID(ctx, uid)
}

func (s *PostgresStore) LinkUserIdentity(ctx context.Context, userID, provider, providerUserID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_identities (user_id, provider, provider_user_id) VALUES ($1, $2, $3) ON CONFLICT (provider, provider_user_id) DO NOTHING`, userID, provider, providerUserID)
	return err
}

func (s *PostgresStore) CreateSAMLServiceProvider(ctx context.Context, sp *SAMLServiceProvider) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO saml_service_providers (id, entity_id, acs_url, certificate, metadata_url) VALUES ($1, $2, $3, $4, $5)`,
		sp.ID, sp.EntityID, sp.ACSURL, sp.Certificate, sp.MetadataURL)
	return err
}

func (s *PostgresStore) GetSAMLServiceProviderByEntityID(ctx context.Context, entityID string) (*SAMLServiceProvider, error) {
	var sp SAMLServiceProvider
	var cert, metaURL sql.NullString
	var createdAt interface{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, entity_id, acs_url, certificate, metadata_url, created_at FROM saml_service_providers WHERE entity_id = $1`,
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

func (s *PostgresStore) ListSAMLServiceProviders(ctx context.Context) ([]SAMLServiceProvider, error) {
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

func (s *PostgresStore) CreateOIDCEnterpriseConnection(ctx context.Context, ec *OIDCEnterpriseConnection) error {
	scope := ec.Scope
	if scope == "" {
		scope = "openid email profile"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_enterprise_connections (id, name, issuer_url, client_id, client_secret, scope, domain_hint) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ec.ID, ec.Name, ec.IssuerURL, ec.ClientID, ec.ClientSecret, scope, ec.DomainHint)
	return err
}

func (s *PostgresStore) GetOIDCEnterpriseConnectionByName(ctx context.Context, name string) (*OIDCEnterpriseConnection, error) {
	var ec OIDCEnterpriseConnection
	var scope, domainHint sql.NullString
	var createdAt interface{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, issuer_url, client_id, client_secret, scope, domain_hint, created_at FROM oidc_enterprise_connections WHERE name = $1`,
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

func (s *PostgresStore) ListOIDCEnterpriseConnections(ctx context.Context) ([]OIDCEnterpriseConnection, error) {
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

func (s *PostgresStore) GetWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, attestation_type, transports, created_at FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var transports sql.NullString
		var createdAt time.Time
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AttestationType, &transports, &createdAt); err != nil {
			return nil, err
		}
		if transports.Valid {
			c.Transports = transports.String
		}
		c.CreatedAt = createdAt
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error {
	transports := cred.Transports
	if transports == "" {
		transports = "[]"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, attestation_type, transports, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		cred.ID, cred.UserID, cred.CredentialID, cred.PublicKey, cred.AttestationType, transports, cred.CreatedAt)
	return err
}

func (s *PostgresStore) AppendLog(ctx context.Context, eventType, userID, clientID, payload string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_logs (event_type, user_id, client_id, payload) VALUES ($1, $2, $3, $4)`,
		eventType, userID, clientID, payload)
	return err
}

func (s *PostgresStore) ListLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, event_type, user_id, client_id, payload, created_at FROM audit_logs ORDER BY id DESC LIMIT $1`, limit)
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

func (s *PostgresStore) GetMFAEnrollment(ctx context.Context, userID string) (*MFAEnrollment, error) {
	var totpSecret, backupCodesJSON sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT totp_secret, backup_codes_hash FROM mfa_enrollment WHERE user_id = $1`, userID).
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

func (s *PostgresStore) SetMFAEnrollment(ctx context.Context, userID, totpSecret string, backupCodeHashes []string) error {
	hashesJSON := "[]"
	if len(backupCodeHashes) > 0 {
		b, err := json.Marshal(backupCodeHashes)
		if err != nil {
			return err
		}
		hashesJSON = string(b)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO mfa_enrollment (user_id, totp_secret, backup_codes_hash) VALUES ($1, $2, $3)
		 ON CONFLICT (user_id) DO UPDATE SET totp_secret = EXCLUDED.totp_secret, backup_codes_hash = EXCLUDED.backup_codes_hash`,
		userID, totpSecret, hashesJSON)
	return err
}

func (s *PostgresStore) AddKnownIP(ctx context.Context, userID, ip string) error {
	if userID == "" || ip == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_known_ips (user_id, ip, last_seen) VALUES ($1, $2, CURRENT_TIMESTAMP)
		 ON CONFLICT (user_id, ip) DO UPDATE SET last_seen = CURRENT_TIMESTAMP`,
		userID, ip)
	return err
}

func (s *PostgresStore) IsIPKnownForUser(ctx context.Context, userID, ip string) (bool, error) {
	if userID == "" || ip == "" {
		return false, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM user_known_ips WHERE user_id = $1 AND ip = $2`, userID, ip).Scan(&count)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *PostgresStore) CreateSMSOTPToken(ctx context.Context, data *SMSOTPTokenData) (string, error) {
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
		`INSERT INTO passwordless_tokens (token, token_type, phone, code, email, client_id, redirect_uri, state, response_type, scope, audience, expires_at) VALUES ($1, 'sms', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		token, data.Phone, data.Code, "sms:"+data.Phone, data.ClientID, data.RedirectURI, data.State, responseType, scope, data.Audience, expiresAt)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *PostgresStore) ConsumeSMSOTPToken(ctx context.Context, token, code string) (*SMSOTPTokenData, bool) {
	if !strings.HasPrefix(token, "sms_") {
		return nil, false
	}
	var phone, clientID, redirectURI, state, responseType, scope, audience sql.NullString
	var storedCode sql.NullString
	var expiresAt time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT phone, code, client_id, redirect_uri, state, response_type, scope, audience, expires_at FROM passwordless_tokens WHERE token = $1 AND token_type = 'sms'`,
		token).Scan(&phone, &storedCode, &clientID, &redirectURI, &state, &responseType, &scope, &audience, &expiresAt)
	if err == sql.ErrNoRows || err != nil {
		return nil, false
	}
	if !storedCode.Valid || storedCode.String != code {
		s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = $1`, token)
		return nil, false
	}
	if time.Now().After(expiresAt) {
		s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = $1`, token)
		return nil, false
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM passwordless_tokens WHERE token = $1`, token)
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

func (s *PostgresStore) ConsumeBackupCode(ctx context.Context, userID, code string) (bool, error) {
	en, err := s.GetMFAEnrollment(ctx, userID)
	if err != nil || en == nil || len(en.BackupCodeHashes) == 0 {
		return false, err
	}
	valid, idx := mfa.VerifyBackupCode(code, en.BackupCodeHashes)
	if !valid {
		return false, nil
	}
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
	_, err = s.db.ExecContext(ctx, `UPDATE mfa_enrollment SET backup_codes_hash = $1 WHERE user_id = $2`, hashesJSON, userID)
	return err == nil, err
}

func (s *PostgresStore) DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *PostgresStore) ListUsersExport(ctx context.Context, page, perPage int) ([]ExportUser, int, error) {
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 100 {
		perPage = 100
	}
	offset := page * perPage

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, display_name, COALESCE(email_verified, false), created_at, app_metadata, user_metadata 
		 FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ExportUser
	for rows.Next() {
		var u ExportUser
		var name sql.NullString
		var createdAt time.Time
		var appMeta, userMeta sql.NullString
		if err := rows.Scan(&u.UserID, &u.Email, &name, &u.EmailVerified, &createdAt, &appMeta, &userMeta); err != nil {
			return nil, 0, err
		}
		if name.Valid {
			u.Name = name.String
		}
		u.CreatedAt = createdAt
		u.AppMetadata = parseJSONMap(appMeta)
		u.UserMetadata = parseJSONMap(userMeta)
		out = append(out, u)
	}

	var total int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&total)
	return out, total, nil
}

// Organizations

func (s *PostgresStore) CreateOrganization(ctx context.Context, org *Organization) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO organizations (id, name, display_name, metadata) VALUES ($1, $2, $3, $4)`,
		org.ID, org.Name, org.DisplayName, jsonBytes(org.Metadata))
	return err
}

func (s *PostgresStore) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	var o Organization
	var displayName, meta sql.NullString
	var createdAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT id, name, display_name, metadata, created_at FROM organizations WHERE id = $1`, id).
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
	o.CreatedAt = createdAt
	return &o, nil
}

func (s *PostgresStore) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, display_name, metadata, created_at FROM organizations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		var displayName, meta sql.NullString
		var createdAt time.Time
		if err := rows.Scan(&o.ID, &o.Name, &displayName, &meta, &createdAt); err != nil {
			return nil, err
		}
		if displayName.Valid {
			o.DisplayName = displayName.String
		}
		o.Metadata = parseJSONMap(meta)
		o.CreatedAt = createdAt
		out = append(out, o)
	}
	return out, nil
}

func (s *PostgresStore) UpdateOrganization(ctx context.Context, id string, updates map[string]interface{}) error {
	var set []string
	var args []interface{}
	n := 1
	if v, ok := updates["name"].(string); ok {
		set = append(set, fmt.Sprintf("name = $%d", n))
		args = append(args, v)
		n++
	}
	if v, ok := updates["display_name"].(string); ok {
		set = append(set, fmt.Sprintf("display_name = $%d", n))
		args = append(args, v)
		n++
	}
	if v, ok := updates["metadata"].(map[string]interface{}); ok {
		set = append(set, fmt.Sprintf("metadata = $%d", n))
		args = append(args, jsonBytes(v))
		n++
	}
	if len(set) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.ExecContext(ctx, `UPDATE organizations SET `+strings.Join(set, ", ")+` WHERE id = $`+fmt.Sprint(n), args...)
	return err
}

func (s *PostgresStore) DeleteOrganization(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	return err
}

func (s *PostgresStore) AddOrgMember(ctx context.Context, orgID, userID, role string) error {
	if role == "" {
		role = "member"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT (org_id, user_id) DO UPDATE SET role = $3`, orgID, userID, role)
	return err
}

func (s *PostgresStore) RemoveOrgMember(ctx context.Context, orgID, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	return err
}

func (s *PostgresStore) ListOrgMembers(ctx context.Context, orgID string) ([]OrgMember, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT org_id, user_id, role FROM org_members WHERE org_id = $1`, orgID)
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

func (s *PostgresStore) IsOrgMember(ctx context.Context, orgID, userID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *PostgresStore) SetOrgConnection(ctx context.Context, orgID, connectionID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO org_connections (org_id, connection_id) VALUES ($1, $2) ON CONFLICT (org_id, connection_id) DO NOTHING`, orgID, connectionID)
	return err
}

func (s *PostgresStore) ListOrgConnections(ctx context.Context, orgID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT connection_id FROM org_connections WHERE org_id = $1`, orgID)
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

func (s *PostgresStore) RemoveOrgConnection(ctx context.Context, orgID, connectionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM org_connections WHERE org_id = $1 AND connection_id = $2`, orgID, connectionID)
	return err
}

func (s *PostgresStore) CreateEnterpriseConnection(ctx context.Context, ec *EnterpriseConnection) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO enterprise_connections (id, org_id, name, domain_hint, issuer_url, client_id, client_secret) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ec.ID, ec.OrgID, ec.Name, ec.DomainHint, ec.IssuerURL, ec.ClientID, ec.ClientSecret)
	return err
}

func (s *PostgresStore) GetEnterpriseConnection(ctx context.Context, id string) (*EnterpriseConnection, error) {
	var ec EnterpriseConnection
	var domainHint, secret sql.NullString
	var createdAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT id, org_id, name, domain_hint, issuer_url, client_id, client_secret, created_at FROM enterprise_connections WHERE id = $1`, id).
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
	ec.CreatedAt = createdAt
	return &ec, nil
}

func (s *PostgresStore) ListEnterpriseConnections(ctx context.Context, orgID string) ([]EnterpriseConnection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, org_id, name, domain_hint, issuer_url, client_id, client_secret, created_at FROM enterprise_connections WHERE org_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnterpriseConnection
	for rows.Next() {
		var ec EnterpriseConnection
		var domainHint, secret sql.NullString
		var createdAt time.Time
		if err := rows.Scan(&ec.ID, &ec.OrgID, &ec.Name, &domainHint, &ec.IssuerURL, &ec.ClientID, &secret, &createdAt); err != nil {
			return nil, err
		}
		if domainHint.Valid {
			ec.DomainHint = domainHint.String
		}
		if secret.Valid {
			ec.ClientSecret = secret.String
		}
		ec.CreatedAt = createdAt
		out = append(out, ec)
	}
	return out, nil
}

func (s *PostgresStore) GetEnterpriseConnectionByDomain(ctx context.Context, domain string) (*EnterpriseConnection, error) {
	var ec EnterpriseConnection
	var domainHint, secret sql.NullString
	var createdAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT id, org_id, name, domain_hint, issuer_url, client_id, client_secret, created_at FROM enterprise_connections WHERE LOWER(domain_hint) = LOWER($1)`, domain).
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
	ec.CreatedAt = createdAt
	return &ec, nil
}

func (s *PostgresStore) CreateInvitation(ctx context.Context, inv *Invitation) (string, error) {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invitations (id, org_id, email, role, token, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		inv.ID, inv.OrgID, inv.Email, inv.Role, inv.Token, inv.ExpiresAt)
	return inv.Token, err
}

func (s *PostgresStore) GetInvitationByToken(ctx context.Context, token string) (*Invitation, error) {
	var inv Invitation
	err := s.db.QueryRowContext(ctx, `SELECT id, org_id, email, role, token, expires_at, created_at FROM invitations WHERE token = $1`, token).
		Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.Token, &inv.ExpiresAt, &inv.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, nil
	}
	return &inv, nil
}

func (s *PostgresStore) ConsumeInvitation(ctx context.Context, token string) (*Invitation, bool) {
	inv, err := s.GetInvitationByToken(ctx, token)
	if err != nil || inv == nil {
		return nil, false
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM invitations WHERE token = $1`, token)
	if err != nil {
		return nil, false
	}
	return inv, true
}

func (s *PostgresStore) SaveCIBARequest(ctx context.Context, req *CIBARequest) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ciba_requests (auth_req_id, client_id, login_hint, scope, audience, status, user_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		req.AuthReqID, req.ClientID, req.LoginHint, req.Scope, req.Audience, req.Status, req.UserID, req.ExpiresAt)
	return err
}

func (s *PostgresStore) GetCIBARequest(ctx context.Context, authReqID string) (*CIBARequest, error) {
	var req CIBARequest
	err := s.db.QueryRowContext(ctx,
		`SELECT auth_req_id, client_id, login_hint, scope, audience, status, user_id, created_at, expires_at FROM ciba_requests WHERE auth_req_id = $1`,
		authReqID,
	).Scan(&req.AuthReqID, &req.ClientID, &req.LoginHint, &req.Scope, &req.Audience, &req.Status, &req.UserID, &req.CreatedAt, &req.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(req.ExpiresAt) {
		return nil, nil
	}
	return &req, nil
}

func (s *PostgresStore) UpdateCIBARequestStatus(ctx context.Context, authReqID, status, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE ciba_requests SET status = $1, user_id = $2 WHERE auth_req_id = $3`,
		status, userID, authReqID)
	return err
}

func (s *PostgresStore) SaveTokenVaultEntry(ctx context.Context, entry *TokenVaultEntry) (string, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE token_vault SET access_token_encrypted = $1, metadata = $2 WHERE name = $3 AND user_id = $4`,
		entry.AccessTokenEncrypted, entry.Metadata, entry.Name, entry.UserID)
	if err != nil {
		return "", err
	}
	aff, _ := res.RowsAffected()
	if aff > 0 {
		var id string
		_ = s.db.QueryRowContext(ctx, `SELECT id FROM token_vault WHERE name = $1 AND user_id = $2`, entry.Name, entry.UserID).Scan(&id)
		return id, nil
	}
	if entry.ID == "" {
		b := make([]byte, 12)
		rand.Read(b)
		entry.ID = "vault_" + hex.EncodeToString(b)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO token_vault (id, name, user_id, access_token_encrypted, metadata) VALUES ($1, $2, $3, $4, $5)`,
		entry.ID, entry.Name, entry.UserID, entry.AccessTokenEncrypted, entry.Metadata)
	return entry.ID, err
}

func (s *PostgresStore) GetTokenVaultEntry(ctx context.Context, name, userID string) (*TokenVaultEntry, error) {
	var e TokenVaultEntry
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, user_id, access_token_encrypted, metadata, created_at FROM token_vault WHERE name = $1 AND user_id = $2`,
		name, userID,
	).Scan(&e.ID, &e.Name, &e.UserID, &e.AccessTokenEncrypted, &e.Metadata, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *PostgresStore) GetTokenVaultEntryByID(ctx context.Context, id string) (*TokenVaultEntry, error) {
	var e TokenVaultEntry
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, user_id, access_token_encrypted, metadata, created_at FROM token_vault WHERE id = $1`,
		id,
	).Scan(&e.ID, &e.Name, &e.UserID, &e.AccessTokenEncrypted, &e.Metadata, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}
