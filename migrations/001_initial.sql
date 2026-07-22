-- Initial schema matching SQLite structure for PostgreSQL

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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS connections (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    strategy TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_blocks (
    user_id TEXT PRIMARY KEY,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_type TEXT,
    user_id TEXT,
    client_id TEXT,
    payload TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed roles and permissions
INSERT INTO roles (id, name, description) VALUES ('rol_default', 'user', 'Default user role')
ON CONFLICT (id) DO NOTHING;
INSERT INTO roles (id, name, description) VALUES ('rol_admin', 'admin', 'Administrator role')
ON CONFLICT (id) DO NOTHING;
INSERT INTO permissions (id, name, resource_server_identifier, description)
VALUES ('perm_read', 'read:users', 'https://api.example.com', 'Read users')
ON CONFLICT (id) DO NOTHING;
INSERT INTO permissions (id, name, resource_server_identifier, description)
VALUES ('perm_write', 'write:users', 'https://api.example.com', 'Write users')
ON CONFLICT (id) DO NOTHING;
INSERT INTO role_permissions (role_id, permission_id) VALUES ('rol_default', 'perm_read')
ON CONFLICT (role_id, permission_id) DO NOTHING;
INSERT INTO role_permissions (role_id, permission_id) VALUES ('rol_admin', 'perm_read')
ON CONFLICT (role_id, permission_id) DO NOTHING;
INSERT INTO role_permissions (role_id, permission_id) VALUES ('rol_admin', 'perm_write')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Seed clients and connections
INSERT INTO clients (id, name, app_type, callbacks, allowed_origins)
VALUES ('e2e-test', 'E2E Test', 'spa', 'http://localhost:3000/callback,http://localhost/callback', 'http://localhost:3000,http://localhost')
ON CONFLICT (id) DO NOTHING;
INSERT INTO clients (id, name, app_type, callbacks, allowed_origins)
VALUES ('default', 'auth0', 'regular_web', 'http://localhost/callback', '')
ON CONFLICT (id) DO NOTHING;
INSERT INTO connections (id, name, strategy)
VALUES ('con_db_main', 'Username-Password-Authentication', 'auth0')
ON CONFLICT (id) DO NOTHING;
